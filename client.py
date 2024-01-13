import argparse
import socket
import sys
import threading
import time

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers
from scapy.sendrecv import sniff, sendp, send

import config
from CustomICMP import CustomICMP
from chksum_calculation import calc_checksum

is_connected = None
destination_mac = "ff:ff:ff:ff:ff:ff"
host = ""
hello_message = "Trying to connect a new client"


def send_icmp_with_data():
    global host, is_connected, destination_mac
    data_to_send = 'echo ' + hello_message
    packet_bytes = bytes(CustomICMP(code=config.REQUEST_CODE) / data_to_send)
    packet = (IP(dst=host) /
              CustomICMP(code=config.REQUEST_CODE, chksum=calc_checksum(packet_bytes)) / data_to_send)
    send(packet, verbose=False)

    time.sleep(10)

    while is_connected:
        data_to_send = input()
        packet_bytes = bytes(CustomICMP(code=config.REQUEST_CODE) / data_to_send)
        packet = (IP(dst=host) /
                  CustomICMP(code=config.REQUEST_CODE, chksum=calc_checksum(packet_bytes)) / data_to_send)
        send(packet, verbose=False)


def packet_callback(packet):
    global destination_mac

    if packet.haslayer(CustomICMP):
        if (hasattr(packet[CustomICMP].payload, 'load') and packet[CustomICMP].code == config.RESPONSE_CODE and
                packet[CustomICMP].id == config.ID):
            print(packet[CustomICMP].payload.load.decode('utf-8'))


def hello_packet_callback(packet):
    global is_connected, destination_mac

    if packet.haslayer(CustomICMP):
        if (packet[CustomICMP].code == config.RESPONSE_CODE and
                packet[CustomICMP].id == config.ID and
                packet[CustomICMP].payload.load.decode('utf-8') == hello_message):
            is_connected = True


if __name__ == '__main__':
    bind_layers(IP, CustomICMP)

    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-t', help='Установка типа ICMP (по умолчанию: 0)')
    # parser.add_argument('host')

    args = parser.parse_args()

    if args.i:
        config.ID = int(args.i)
    if args.t:
        config.TYPE = 5
    host = "192.168.0.60"  # args.host
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
