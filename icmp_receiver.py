import os
import struct
import socket


def reply_to_ping_request():
    # Создание сокета для приема ICMP пакетов
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    while True:
        sock.bind(("192.168.0.54", 139))
        data, addr = sock.recvfrom(1024)
        ip_header = data[:20]  # Первые 20 байт - заголовок IP
        icmp_header = data[20:28]  # Следующие 8 байт - заголовок ICMP

        # Распаковка данных из ICMP заголовка
        icmp_type, icmp_code, _, _, _ = struct.unpack('!BBHHH', icmp_header)

        # Проверка типа и кода ICMP пакета (Echo Request)
        if icmp_type == 8 and icmp_code == 0:
            # Генерация ICMP Echo Reply (тип 0)
            icmp_reply = struct.pack('!BBHHH', 0, 0, 0, 1, 1) + data[8:]

            # Вычисление контрольной суммы для ICMP Echo Reply
            checksum = calculate_checksum(icmp_reply)
            icmp_reply = struct.pack('!BBHHH', 0, 0, checksum, 1, 1) + data[8:]

            # Отправка ICMP Echo Reply
            sock.sendto(icmp_reply, addr)
            print('Sent ICMP Echo Reply to', addr)


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
    reply_to_ping_request()
