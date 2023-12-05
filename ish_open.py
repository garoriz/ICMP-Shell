import os
import subprocess


def popen2(commandString):
    parent_conn, child_conn = os.pipe()

    process = subprocess.Popen(
        ["cmd", "/c", commandString],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True
    )

    os.close(parent_conn) if parent_conn != -1 else None

    return child_conn, process
