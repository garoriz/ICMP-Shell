from scapy.fields import XByteField, XShortField
from scapy.packet import Packet

import config


class CustomICMP(Packet):
    name = "CustomICMP"
    fields_desc = [XByteField("type", config.TYPE),
                   XByteField("code", config.REQUEST_CODE),
                   XShortField("id", config.ID),
                   XShortField("seq", config.SEQ),
                   XShortField("chksum", config.REQUEST_CODE)]
