import socket
import struct
import sys

CNTRL_CEXIT = 1
CNTRL_CPOUT = 2


# Mock ish_info and sendhdr for demonstration purposes
class ish_info:
    id = 1515
    type = 0
    packetsize = 512
    seq = 0


class sendhdr:
    cntrl = 0


def ish_send(sockfd, send_buf, sin):
    datalen = struct.calcsize('!BBHHH') + struct.calcsize('!II') + len(send_buf)
    datagram = bytearray(datalen)

    icmph = struct.Struct('!BBHHH')
    ish_hdr = struct.Struct('!II')

    icmph.pack_into(datagram, 0, ish_info.type, 0, 0, ish_info.id, ish_info.seq)
    ish_hdr.pack_into(datagram, struct.calcsize('!BBHHH'), sendhdr.cntrl, 0)

    data_offset = struct.calcsize('!BBHHH') + struct.calcsize('!II')
    datagram[data_offset:data_offset + len(send_buf)] = send_buf.encode()

    # Calculate ICMP checksum
    icmph_checksum = struct.pack('!H', 0)
    icmph_checksum = struct.pack('!H', sum(struct.unpack('!HHHHH', datagram[:10])) + sum(
        struct.unpack('!HH' + str(len(send_buf)) + 's', datagram[16:] + b'\0' * (len(send_buf) % 2))))

    datagram[10:12] = icmph_checksum

    # Send the datagram
    try:
        sockfd.sendto(datagram, sin)
    except socket.error as e:
        sys.exit(f"Error: {e}")


def ish_recv(sockfd, sin):
    datalen = ish_info.packetsize + struct.calcsize('!BBHHH') + struct.calcsize('!II')
    datagram = bytearray(datalen)

    try:
        n, addr = sockfd.recvfrom_into(datagram, sizeof(datagram))
    except socket.error as e:
        sys.exit(f"Error: {e}")

    icmph = struct.unpack('!BBHHH', datagram[:8])
    ish_hdr = struct.unpack('!II', datagram[8:16])
    data = datagram[16:]

    if icmph[3] != ish_info.id:
        return -1

    if recv_buf is not None:
        recv_buf.clear()
        recv_buf.extend(data.decode())

    if ish_hdr[0] & CNTRL_CEXIT:
        return CNTRL_CEXIT
    elif ish_hdr[0] & CNTRL_CPOUT:
        return CNTRL_CPOUT

    return 0


def error_msg():
    print(f"Error: {errno}")


def in_cksum(addr, length):
    nleft = length
    sum = 0
    w = addr
    answer = 0

    while nleft > 1:
        sum += w[0]
        sum = (sum & 0xFFFF) + (sum >> 16)
        nleft -= 2
        w = w[1:]

    if nleft == 1:
        sum += ord(w[0])

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    answer = ~sum & 0xFFFF
    return answer


# Mock socket creation for demonstration purposes
sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sin = ('example.com', 12345)  # Replace with actual address and port

# Mock send_buf for demonstration purposes
send_buf = "Hello, server!"

ish_send(sockfd, send_buf, sin)
result = ish_recv(sockfd, sin)
print(result)
