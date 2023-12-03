import struct
import socket
import sys
import os
import signal
import errno
from typing import Tuple

from _ctypes import sizeof


class IshHdr:
    def __init__(self, cntrl: int, ts: int):
        self.cntrl = cntrl
        self.ts = ts


class IshTrack:
    def __init__(self, _id: int, _type: int, packetsize: int, seq: int):
        self.id = _id
        self.type = _type
        self.packetsize = packetsize
        self.seq = seq


VERSION = "1.0"

CNTRL_CEXIT = 1
CNTRL_CPOUT = 2


def error_msg(strerror):
    print(f"Error: {strerror}.")
    sys.exit(-1)


def in_cksum(data: bytes) -> int:
    n = len(data)
    s = 0
    for i in range(0, n, 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff

    return s


def ish_recv(sockfd, sin):
    datalen = ish_info.packetsize + struct.calcsize('!BBHHH')

    datagram = bytearray(datalen)
    n, addr = sockfd.recvfrom_into(datagram, sizeof(datagram))

    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', datagram[20:28])

    if icmp_id != ish_info.id:
        return -1

    data = datagram[28:]

    if recv_buf is not None:
        recv_buf.clear()
        recv_buf.extend(data)

    if recvhdr.cntrl & CNTRL_CEXIT:
        return CNTRL_CEXIT
    elif recvhdr.cntrl & CNTRL_CPOUT:
        return CNTRL_CPOUT

    return 0


ish_info = IshTrack(_id=1515, _type=0, packetsize=512, seq=0)
sendhdr = IshHdr(0, 0)
