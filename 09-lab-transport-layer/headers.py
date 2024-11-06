from __future__ import annotations

import struct

from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str


IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20
TCPIP_HEADER_LEN = IP_HEADER_LEN + TCP_HEADER_LEN
UDPIP_HEADER_LEN = IP_HEADER_LEN + UDP_HEADER_LEN

TCP_RECEIVE_WINDOW = 64

class IPv4Header:
    def __init__(self, length: int, ttl: int, protocol: int, checksum: int,
            src: str, dst: str) -> IPv4Header:
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst

    @classmethod
    def from_bytes(cls, hdr: bytes) -> IPv4Header:
        version_ihl, tos, total_length, id, flags_fragment, ttl, protocol, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', hdr)
        length = total_length
        src = ip_binary_to_str(src)
        dst = ip_binary_to_str(dst)
        return cls(length, ttl, protocol, checksum, src, dst)

    def to_bytes(self) -> bytes:
        version_ihl = (4 << 4) | 5  # IPv4 and 5 32-bit words in header
        tos = 0
        id = 0
        flags_fragment = 0
        src_bytes = ip_str_to_binary(self.src)
        dst_bytes = ip_str_to_binary(self.dst)
        return struct.pack('!BBHHHBBH4s4s', version_ihl, tos, self.length, id, flags_fragment, 
                           self.ttl, self.protocol, self.checksum, src_bytes, dst_bytes)


class UDPHeader:
    def __init__(self, sport: int, dport: int, length: int,
            checksum: int) -> UDPHeader:
        self.sport = sport
        self.dport = dport
        self.checksum = checksum
        self.length = length

    @classmethod
    def from_bytes(cls, hdr: bytes) -> UDPHeader:
        sport, = struct.unpack('!H', hdr[:2])
        dport, = struct.unpack('!H', hdr[2:4])
        length, = struct.unpack('!H', hdr[4:6])
        checksum, = struct.unpack('!H', hdr[6:8])
        return cls(sport, dport, length, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!H', self.length)
        hdr += struct.pack('!H', self.checksum)
        return hdr


class TCPHeader:
    def __init__(self, sport: int, dport: int, seq: int, ack: int,
            flags: int, checksum: int) -> TCPHeader:
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.checksum = checksum
        self.window = TCP_RECEIVE_WINDOW  # Add this line

    @classmethod
    def from_bytes(cls, hdr: bytes) -> TCPHeader:
        if len(hdr) < 20:
            raise ValueError("TCP header must be at least 20 bytes")
        
        sport, dport, seq, ack, offset_flags, window, checksum, urgent_ptr = struct.unpack('!HHIIHHHH', hdr[:20])
        data_offset = (offset_flags >> 12) * 4
        flags = offset_flags & 0x3F
        
        if len(hdr) < data_offset:
            raise ValueError(f"TCP header length ({len(hdr)}) is less than data offset ({data_offset})")
        
        tcp_header = cls(sport, dport, seq, ack, flags, checksum)
        tcp_header.window = window  # Set the window size
        return tcp_header

    def to_bytes(self) -> bytes:
        offset_flags = (5 << 12) | self.flags  # 5 32-bit words in header
        return struct.pack('!HHIIHHHHH', 
                        self.sport, 
                        self.dport, 
                        self.seq, 
                        self.ack,
                        offset_flags, 
                        self.window,
                        self.checksum, 
                        0,  # Urgent pointer, set to 0
                        0)  # Options, set to 0
