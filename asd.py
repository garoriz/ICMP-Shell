import asyncio
import subprocess
import sys
import threading
import time
from threading import Thread

import pexpect
from Demos.print_desktop import p


def readstdout():
    for l in iter(p.stdout.readline, b""):
        sys.stdout.write(f'{l.decode("utf-8", "backslashreplace")}\n')

# Function to read and print stderr of the subprocess
def readstderr():
    for l in iter(p.stderr.readline, b""):
        sys.stderr.write(f'{l.decode("utf-8", "backslashreplace")}\n')

# Function to send a command to the subprocess
def sendcommand(cmd):
    p.stdin.write(cmd.encode() + b"\n")
    p.stdin.flush()

if __name__ == "__main__":
    p = subprocess.Popen(
        "cmd.exe",
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Create two threads to read and print stdout and stderr concurrently
    t1 = threading.Thread(target=readstdout)
    t2 = threading.Thread(target=readstderr)

    # Start the threads to capture and print the subprocess output
    t1.start()
    t2.start()

    # Send a command to the subprocess
    sendcommand("echo hello")
    sendcommand("cd..")
    sendcommand("dir")
    #cat = subprocess.Popen('cmd.exe', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    #cat.stdin.flush()
    #print(cat.stdout.readlines())
    #cat.stdin.write(b"ipconfig\n")
    #cat.stdin.flush()
    #print(cat.stdout.readline().decode('cp866'))
