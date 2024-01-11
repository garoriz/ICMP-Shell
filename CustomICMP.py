from scapy.fields import XByteField, XShortField
from scapy.packet import Packet

import config


class CustomICMP(Packet):
    name = "CustomICMP"
    fields_desc=[ XByteField("type",config.TYPE),
                  XByteField("code", 0),
                  XShortField("id", 1515),
                 IntEnumField("donald" , 1 ,
                      { 1: "happy", 2: "cool" , 3: "angry" } ) ]