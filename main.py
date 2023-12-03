import argparse
import signal
import sys
import socket

import ish_main
import ishell


def ish_timeout():
    print("failed.")
    sys.exit(-1)


def main():
    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')
    #parser.add_argument('host')

    args = parser.parse_args()

    if args.i:
        ishell.ish_info.id = args.i
    if args.t:
        ishell.ish_info.type = args.t
    if args.p:
        ishell.ish_info.packetsize = args.p
    host = "127.0.0.1"
    try:
        host_string = socket.gethostbyname(host)
    except socket.gaierror:
        print("Error: Cannot resolve " + host + "!")
        sys.exit(-1)

    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print(e)

    ishell.sendhdr.cntrl = 0
    ishell.sendhdr.cntrl |= ishell.CNTRL_CPOUT

    print(f"ICMP Shell v{ishell.VERSION}  (client)")
    print("--------------------------------------------------")
    print(f"Connecting to {host}...")

    sin = (host_string, 0)
    if (ish_main.ish_send(sockfd, "id\n", sin)) < 0:
        print("Failed.\n")

    signal.signal(signal.SIGALRM, ish_timeout)

    timeout_seconds = 10
    signal.alarm(timeout_seconds)


if __name__ == '__main__':
    main()
