def calc_checksum(packet: bytes) -> int:
    words = [int.from_bytes(packet[_:_ + 2], "big") for _ in range(0, len(packet), 2)]
    print(words)
    checksum = sum(words)
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return 0xffff - checksum
