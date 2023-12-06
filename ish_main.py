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
    datalen = ishell.ish_info.packetsize + struct.calcsize('!BBHHH') + struct.calcsize('!HI')

    try:
        datagram, addr = sockfd.recvfrom(1024)
    except socket.error as e:
        print("Error receiving data:", e)
        return -1
    print(datagram.decode('cp1251'))

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
