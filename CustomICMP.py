from scapy.fields import XByteField, XShortField
from scapy.packet import Packet

import config


class CustomICMP(Packet):
    name = "CustomICMP"
    fields_desc = [XByteField("type", config.TYPE),
                   XByteField("code", 0),
                   XShortField("id", config.ID),
                   XShortField("seq", 0),
                   XShortField("chksum", 0)]
