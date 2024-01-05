import platform
import subprocess
import sys
import threading

if __name__ == "__main__":
    os_name = platform.system()

    # Выводим результат
    print("Операционная система:", os_name)
