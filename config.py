import platform

ID = 1515
TYPE = 0
REQUEST_CODE = 16
RESPONSE_CODE = 17

terminal_name = ""
os_name = platform.system()
if os_name == "Windows":
    terminal_name = "cmd.exe"
if os_name == "Linux":
    terminal_name = "bash"

