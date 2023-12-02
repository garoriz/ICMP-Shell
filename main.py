import argparse
import sys

import ishell


def usage(program: str) -> None:
    print(f"ICMP Shell v{ishell.VERSION} (client)\n"
          f"usage: {program} [options] <host>\n\n"
          f"options:\n"
          f" -i <id>          Set session id; range: 0-65535 (default: 1515)\n"
          f" -t <type>        Set ICMP type (default: 0)\n"
          f" -p <packetsize>  Set packet size (default: 512)\n"
          f"\nexample:\n"
          f"{program} -i 65535 -t 0 -p 1024 host.com\n")
    sys.exit(-1)


def main():
    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')

    # Парсинг аргументов
    args = parser.parse_args()

    # Взаимодействие с аргументами
    if args.i:
        print('*Имитация работы*')
    else:
        print(usage(__file__.split('\\')[-1]))


if __name__ == '__main__':
    main()
