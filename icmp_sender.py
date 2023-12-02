import code
import os
import platform
import socket
import struct
import sys
import time


def send_ping_request(host):
    try:
        # Определение типа ОС
        os_type = platform.system().lower()

        # Создание сокета
        if os_type == 'windows':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        else:
            # Для Linux требуются привилегии root
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)

        # Генерация ICMP Echo Request (тип 8)
        icmp_header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        checksum = calculate_checksum(icmp_header)

        # Генерация ICMP пакета с контрольной суммой
        icmp_packet = struct.pack('!BBHHH', 8, 0, checksum, 1, 1)

        # Отправка пакета на хост
        sock.sendto(icmp_packet, (host, 0))

        # Закрытие сокета
        sock.close()

        print('Ping request sent successfully to', host)

    except socket.error as e:
        print('Failed to send ping request:', str(e))


def calculate_checksum(data):
    # Вычисление контрольной суммы ICMP пакета
    checksum = 0
    count_to = (len(data) // 2) * 2

    for count in range(0, count_to, 2):
        this_val = data[count + 1] * 256 + data[count]
        checksum += this_val
        checksum &= 0xffffffff

    if count_to < len(data):
        checksum += data[count_to]
        checksum &= 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    return (~checksum) & 0xffff


if __name__ == '__main__':
    host = '192.168.0.54'  # Хост для проверки доступности
    send_ping_request(host)
