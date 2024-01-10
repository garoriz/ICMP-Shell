import platform
import subprocess

terminal_name = ""
os_name = platform.system()
if os_name == "Windows":
    terminal_name = "cmd.exe"
if os_name == "Linux":
    terminal_name = "bash"

p = subprocess.Popen(
    terminal_name,
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True
)
