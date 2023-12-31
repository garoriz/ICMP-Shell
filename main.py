import argparse
import os
import signal
import sys
import socket
import asyncio
import threading
import time

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.sendrecv import send, sniff, sr1, sendp, AsyncSniffer

import ish_main
import ish_open
import ishell
from util.Ticker import Ticker

is_connected = False


async def send_icmp(target_ip, data_to_send):
    packet = IP(dst=target_ip) / ICMP(type=0, id=1515) / data_to_send
    send(packet, verbose=False)
    # x = Ether(src='f0:d4:15:84:6b:65', dst='08:00:27:0f:73:c0')
    # sendp(x)


async def receive_icmp():
    sniff(filter="icmp", prn=packet_callback, timeout=1, store=False)


async def receive_hello_icmp():
    sniff(filter="icmp", prn=hello_packet_callback, timeout=1, store=False)


def send_icmp_with_data(target_ip, data):
    packet = IP(dst=target_ip) / ICMP() / data
    send(packet)


def ish_timeout():
    print("failed.")
    sys.exit(-1)


def packet_callback(packet):
    if ICMP in packet and packet[ICMP].id == 1515:
        s = packet[ICMP].payload.load.decode('utf-8')
        print(packet[ICMP].payload.load.decode('utf-8'), end='')


def hello_packet_callback(packet):
    global is_connected
    if ICMP in packet and packet[ICMP].id == 1515 and packet[ICMP].payload.load.decode(
            'utf-8') == 'hello':
        is_connected = True
        print("done.")


# def main():
#    parser = argparse.ArgumentParser(description='ICMP Shell')
#
#    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
#    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
#    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')
#    # parser.add_argument('host')
#
#    args = parser.parse_args()
#
#    if args.i:
#        ishell.ish_info.id = args.i
#    if args.t:
#        ishell.ish_info.type = args.t
#    if args.p:
#        ishell.ish_info.packetsize = args.p
#    host = "192.168.0.1"
#    try:
#        host_string = socket.gethostbyname(host)
#    except socket.gaierror:
#        print("Error: Cannot resolve " + host + "!")
#        sys.exit(-1)
#
#    data_to_send = b"ipconfig"
#
#    send_icmp_with_data(host_string, data_to_send)
#    sniff(filter="icmp", prn=packet_callback)
#    # try:
#    #    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
#    # except socket.error as e:
#    #    print(e)


#
# ishell.sendhdr.cntrl = 0
# ishell.sendhdr.cntrl |= ishell.CNTRL_CPOUT
#
# print(f"ICMP Shell v{ishell.VERSION}  (client)")
# print("--------------------------------------------------")
# print(f"Connecting to {host}...")
#
# sin = (host_string, 0)
# if (ish_main.ish_send(sockfd, "id\n", sin)) < 0:
#    print("Failed.\n")
#
# if ish_main.ish_recv(sockfd, None) < 0:
#    print("Failed.\n")
#    sys.exit(-1)
#
# print("done.")

async def main():
    data_to_send = input()
    send_task = asyncio.create_task(send_icmp(host, data_to_send))
    receive_task = asyncio.create_task(receive_icmp())
    await asyncio.gather(send_task, receive_task)


async def check_connection():
    data_to_send = 'echo hello'
    send_task = asyncio.create_task(send_icmp(host, data_to_send))
    receive_task = asyncio.create_task(receive_hello_icmp())
    await asyncio.gather(send_task, receive_task)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')
    # parser.add_argument('host')

    args = parser.parse_args()

    if args.i:
        ishell.ish_info.id = args.i
    if args.t:
        ishell.ish_info.type = args.t
    if args.p:
        ishell.ish_info.packetsize = args.p
    host = "192.168.0.54"
    try:
        host_string = socket.gethostbyname(host)
    except socket.gaierror:
        print("Error: Cannot resolve " + host + "!")
        sys.exit(-1)

    print("ICMP Shell (client)")
    print("-------------------")
    print("Connecting to " + host + "...")

    asyncio.run(check_connection())

    while is_connected:
        asyncio.run(main())

    if not is_connected:
        print("failed.")
    # data_to_send = b"ipconfig"
#
# send_icmp_with_data(host_string, data_to_send)
# sniff(filter="icmp", prn=packet_callback)
# try:
#    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# except socket.error as e:
#    print(e)
