import argparse
import asyncio
import socket
import sys
import threading
import time

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import send, sniff

import ishell

is_connected = None
host = "192.168.0.60"


def wait_connection():
    while True:
        if not is_connected:
            sys.exit()
        elif is_connected:
            break


def send_icmp_with_data():
    global host
    data_to_send = 'echo hello'
    packet = IP(dst=host) / ICMP(id=1515) / data_to_send
    send(packet, verbose=False)

    wait_connection()

    while is_connected:
        data_to_send = input()
        packet = IP(dst=host) / ICMP(id=1515) / data_to_send
        send(packet, verbose=False)


def receive_icmp_with_data():
    sniff(filter="icmp", prn=hello_packet_callback, timeout=10)

    if not is_connected:
        sys.exit()

    print("done.")

    sniff(filter="icmp", prn=packet_callback)


def check_connection():
    global is_connected
    timeout = 10
    start_time = time.time()

    while True:
        if is_connected:
            break

        elapsed_time = time.time() - start_time
        if elapsed_time >= timeout and is_connected is None:
            is_connected = False
            print("failed.")
            sys.exit()

        time.sleep(1)


async def send_icmp(target_ip, data_to_send):
    if data_to_send.strip() != "":
        packet = IP(dst=target_ip) / ICMP(id=1515) / data_to_send
        send(packet, verbose=False)
    # x = Ether(src='f0:d4:15:84:6b:65', dst='08:00:27:0f:73:c0')
    # sendp(x)


async def receive_icmp():
    sniff(filter="icmp", prn=packet_callback, timeout=1)


async def receive_hello_icmp():
    sniff(filter="icmp", prn=hello_packet_callback, timeout=3)


def packet_callback(packet):
    global is_connected

    if ICMP in packet and packet[ICMP].id == 1515:
        print(packet[ICMP].payload.load.decode('utf-8'))


def hello_packet_callback(packet):
    global is_connected
    if ICMP in packet and packet[ICMP].id == 1515 and packet[ICMP].payload.load.decode('utf-8') == 'hello':
        is_connected = True


async def main():
    data_to_send = input()
    send_task = asyncio.create_task(send_icmp(host, data_to_send))
    receive_task = asyncio.create_task(receive_icmp())
    await asyncio.gather(send_task, receive_task)


# async def check_connection():
#    data_to_send = 'echo hello'
#    send_task = asyncio.create_task(send_icmp(host, data_to_send))
#    receive_task = asyncio.create_task(receive_hello_icmp())
#    await asyncio.gather(send_task, receive_task)


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
    host = "192.168.0.60"
    try:
        host_string = socket.gethostbyname(host)
    except socket.gaierror:
        print("Error: Cannot resolve " + host + "!")
        sys.exit(-1)

    print("ICMP Shell (client)")
    print("-------------------")
    print("Connecting to " + host + "...")

    t1 = threading.Thread(target=send_icmp_with_data)
    #t2 = threading.Thread(target=receive_icmp_with_data)
    #t3 = threading.Thread(target=check_connection)

    t1.start()
    #t2.start()
    #t3.start()

    sniff(filter="icmp", prn=hello_packet_callback, timeout=10)

    if is_connected is None:
        is_connected = False
        print("failed.")
    elif is_connected:
        print("done.")
        sniff(filter="icmp", prn=packet_callback)

    # asyncio.run(check_connection())
#
# while is_connected:
#    asyncio.run(main())
##
# if not is_connected:
#    print("failed.")
