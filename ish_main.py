import socket
import struct
import sys

import ishell

CNTRL_CEXIT = 1
CNTRL_CPOUT = 2


class sendhdr:
    cntrl = 0


def ish_send(_sockfd, _send_buf, _sin):
    ish_hdr_format = '!HI'
    icmp_format = '!BBHHH'

    ish_hdr = struct.pack(ish_hdr_format, ishell.ish_info.type, ishell.ish_info.id)
    icmp_data = struct.pack(icmp_format, ishell.ish_info.type, 0, ishell.ish_info.id, ishell.ish_info.seq, 0)

    datagram = ish_hdr + _send_buf.encode('utf-8') + icmp_data

    icmp_cksum = in_cksum(datagram)
    icmp_data = struct.pack(
        icmp_format,
        ishell.ish_info.type,
        0,
        ishell.ish_info.id,
        ishell.ish_info.seq,
        icmp_cksum
    )

    datagram = ish_hdr + _send_buf.encode('utf-8') + icmp_data

    try:
        _sockfd.sendto(datagram, _sin)
    except socket.error as e:
        print(e)
        return -1

    return 0


def ish_recv(sockfd, recv_buf):
    packetsize = ishell.ish_info.packetsize
    datalen = packetsize + struct.calcsize('!BBHHH') + struct.calcsize('!HI')

    datagram = bytearray(datalen)
    data_offset = struct.calcsize('!BBHHH') + struct.calcsize('!HI')

    try:
        datagram, addr = sockfd.recvfrom(datalen)
    except socket.error as e:
        print("Error receiving data:", e)
        return -1

    icmph = struct.unpack('!BBHHH', datagram[data_offset:data_offset + struct.calcsize('!BBHHH')])
    recvhdr = struct.unpack('!BBHHHHIBBHHHHI',
                            datagram[data_offset + struct.calcsize('!BBHHH'):data_offset + struct.calcsize('!HI')])
    data = datagram[data_offset + struct.calcsize('!HI'):]

    if icmph[3] != ishell.ish_info.id:
        return -1

    if recv_buf is not None:
        recv_buf.clear()
        recv_buf.extend(data[:len(data)].decode())

    if recvhdr[1] & CNTRL_CEXIT:
        return CNTRL_CEXIT
    elif recvhdr[1] & CNTRL_CPOUT:
        return CNTRL_CPOUT

    return 0


def in_cksum(data):
    nleft = len(data)
    _sum = 0
    index = 0

    while nleft > 1:
        word = (data[index + 1] << 8) + data[index]
        _sum += word
        index += 2
        nleft -= 2

    if nleft == 1:
        _sum += data[-1]

    _sum = (_sum >> 16) + (_sum & 0xffff)
    _sum += (_sum >> 16)

    answer = ~_sum & 0xffff
    return answer

# Example usage:
# data = bytearray(b'example_data')  # Replace with your actual data
# checksum = in_cksum(data)
# print("Checksum:", checksum)
