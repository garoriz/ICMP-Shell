import platform
import subprocess

terminal_name = "/bin/sh"
os_name = platform.system()
if os_name == "Windows":
    terminal_name = "cmd.exe"

p = subprocess.Popen(
    terminal_name,
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True
)
