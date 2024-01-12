from scapy.fields import XByteField, XShortField
from scapy.packet import Packet

import config


class CustomICMP(Packet):
    name = "CustomICMP"
    fields_desc = [XByteField("type", config.TYPE),
                   XByteField("code", 0),
                   XShortField("id", 1515),
                   XShortField("seq", 0),
                   XShortField("chksum", 0)]
