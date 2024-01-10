from scapy.all import *
from scapy.layers.inet import ICMP


class CustomICMPField(StrField):
    holds_packet = 1

    def myfmtrepr(self, pkt, x):
        if isinstance(x, bytes):
            return repr(x.decode("utf-8"))
        else:
            return repr(x)

    def i2repr(self, pkt, x):
        return self.myfmtrepr(pkt, x)

    def i2m(self, pkt, x):
        return x.encode("utf-8")

    def m2i(self, pkt, x):
        return x.encode("utf-8")


class CustomICMPPacket(ICMP):
    name = "CustomICMPPacket"
    fields_desc = [IntField("ish_type", 0)]
