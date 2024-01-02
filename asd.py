import subprocess
import sys
import threading

p = subprocess.Popen(
    "bash",
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True
)


def readstdout():
    for l in iter(p.stdout.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        sys.stdout.write(string + "\n")


# Function to read and print stderr of the subprocess
def readstderr():
    for l in iter(p.stderr.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        sys.stderr.write(string + "\n")

def sendcommand(cmd):
    p.stdin.write(cmd.encode() + b"\n")
    p.stdin.flush()

if __name__ == "__main__":
    t1 = threading.Thread(target=readstdout)
    t2 = threading.Thread(target=readstderr)

    t1.start()
    t2.start()
    while True:
        s = input()
        sendcommand(s)
