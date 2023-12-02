import socket
import struct
import sys
import time


def checksum(data):
    # Вычисление контрольной суммы ICMP
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        s += w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff

    return s


def receive_ping(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        icmp_header = data[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

        if type == 0 and code == 0:
            print(f"Ping ответ от {addr[0]}: время={time.time() - struct.unpack('d', data[28:])[0]} ms")


def main():
    try:
        # Создание сокета RAW
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Присваивание сокету адреса и порта
        sock.bind(("0.0.0.0", 0))

        print("Приемник ICMP запущен. Ожидание пакетов...")

        receive_ping(sock)

    except socket.error as e:
        print(f"Ошибка сокета: {e}")
        sys.exit()


if __name__ == "__main__":
    main()
