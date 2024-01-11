import argparse
import socket
import sys
import threading
import time

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp

import config

is_connected = None
destination_mac = "ff:ff:ff:ff:ff:ff"
host = ""
data_to_send = None
hello_message = "Trying to connect a new client"


def send_icmp_with_data():
    global host, data_to_send, is_connected, destination_mac
    data_to_send = 'echo ' + hello_message
    packet = Ether(dst=destination_mac) / IP(dst=host) / ICMP(id=config.ID, type=config.TYPE,
                                                              code=config.REQUEST_CODE) / data_to_send
    sendp(packet, verbose=False)

    time.sleep(10)

    while is_connected:
        data_to_send = input()
        if destination_mac == "00:00:00:00:00:00":
            destination_mac = "ff:ff:ff:ff:ff:ff"
        packet = Ether(dst=destination_mac) / IP(dst=host) / ICMP(id=config.ID, type=config.TYPE,
                                                                  code=config.REQUEST_CODE) / data_to_send
        sendp(packet, verbose=False)


def packet_callback(packet):
    global destination_mac

    if hasattr(packet[ICMP].payload, 'load'):
        if (packet[IP].src == host and packet[ICMP].code == config.RESPONSE_CODE and packet[ICMP].id == config.ID and
                packet[ICMP].type == config.TYPE and packet[ICMP].payload.load.decode('utf-8') != data_to_send):
            destination_mac = packet[Ether].src
            print(packet[ICMP].payload.load.decode('utf-8'))


def hello_packet_callback(packet):
    global is_connected

    if (packet[IP].src == host and packet[ICMP].code == config.RESPONSE_CODE and packet[ICMP].id == config.ID and
            packet[ICMP].type == config.TYPE and packet[ICMP].payload.load.decode('utf-8') == hello_message):
        is_connected = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-t', help='Установка типа ICMP (по умолчанию: 0)')
    parser.add_argument('host')

    args = parser.parse_args()

    if args.i:
        config.ID = int(args.i)
    if args.t:
        config.TYPE = int(args.t)
    host = args.host
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
