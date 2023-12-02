import getopt
import socket
import sys
import signal
from array import array
from typing import Tuple

import select

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


if __name__ == '__main__':
    main()
