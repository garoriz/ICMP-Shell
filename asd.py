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
    frgrnd_wndw = win32gui.GetForegroundWindow()
    wndw_title = win32gui.GetWindowText(frgrnd_wndw)
    if wndw_title.endswith("ishd.exe"):
        win32gui.ShowWindow(frgrnd_wndw, win32con.SW_HIDE)
