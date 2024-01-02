import asyncio
import subprocess
import sys
import threading
import time
from threading import Thread
import win32gui, win32con

import pexpect
from Demos.print_desktop import p

if __name__ == "__main__":
    command = "ls -l"
    result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, text=True)

    # Получить вывод команды
    output = result.stdout
    print(output)
