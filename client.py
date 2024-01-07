import argparse
import socket
import sys
import threading
import time

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import send, sniff

import config

is_connected = None
host = "192.168.0.60"
data_to_send = None


def send_icmp_with_data():
    global host, data_to_send, is_connected
    data_to_send = 'echo hello'
    packet = IP(dst=host) / ICMP(id=config.ID) / data_to_send
    send(packet, verbose=False)

    time.sleep(10)

    while is_connected:
        data_to_send = input()
        packet = IP(dst=host) / ICMP(id=config.ID) / data_to_send
        send(packet, verbose=False)


def packet_callback(packet):
    if ICMP in packet and packet[ICMP].ID == config.ID and packet[ICMP].payload.load.decode('utf-8') != data_to_send:
        print(packet[ICMP].payload.load.decode('utf-8'))


def hello_packet_callback(packet):
    global is_connected
    if ICMP in packet and packet[ICMP].ID == config.ID and packet[ICMP].payload.load.decode('utf-8') == 'hello':
        is_connected = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    # parser.add_argument('host')

    args = parser.parse_args()

    if args.i:
        config.ID = args.i
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

    t1.start()

    sniff(filter="icmp", prn=hello_packet_callback, timeout=10)

    if is_connected is None:
        is_connected = False
        print("failed.")
    elif is_connected:
        print("done.")
        sniff(filter="icmp", prn=packet_callback)
