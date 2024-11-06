from __future__ import annotations

import random

TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_ACK = 0x10

TCP_STATE_LISTEN = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_SYN_RECEIVED = 2
TCP_STATE_ESTABLISHED = 3
TCP_STATE_FIN_WAIT_1 = 4
TCP_STATE_FIN_WAIT_2 = 5
TCP_STATE_CLOSE_WAIT = 6
TCP_STATE_CLOSING = 7
TCP_STATE_LAST_ACK = 8
TCP_STATE_TIME_WAIT = 9
TCP_STATE_CLOSED = 10

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN


#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class UDPSocket:
    def __init__(self, local_addr: str, local_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> UDPSocket:

        self._local_addr = local_addr
        self._local_port = local_port
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        self.buffer = []

    def handle_packet(self, pkt: bytes) -> None:
        # Parse IP header
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        
        # Parse UDP header
        udp_hdr = UDPHeader.from_bytes(pkt[IP_HEADER_LEN:UDPIP_HEADER_LEN])
        
        # Extract data
        data = pkt[UDPIP_HEADER_LEN:]
        
        # Append to buffer
        self.buffer.append((data, ip_hdr.src, udp_hdr.sport))
        
        # Notify application
        self._notify_on_data()

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int, data: bytes=b'') -> bytes:
        # Create IP header
        ip_header = IPv4Header(20 + 8 + len(data), 64, IPPROTO_UDP, 0, src, dst)
        
        # Create UDP header
        udp_header = UDPHeader(sport, dport, 8 + len(data), 0)
        
        # Combine headers and data
        return ip_header.to_bytes() + udp_header.to_bytes() + data


    def send_packet(self, remote_addr: str, remote_port: int, data: bytes) -> None:
        # Create the packet
        packet = self.create_packet(self._local_addr, self._local_port, remote_addr, remote_port, data)
        
        # Send the packet
        self._send_ip_packet(packet)


    def recvfrom(self) -> tuple[bytes, str, int]:
        return self.buffer.pop(0)

    def sendto(self, data: bytes, remote_addr: str, remote_port: int) -> None:
        self.send_packet(remote_addr, remote_port, data)


class TCPSocketBase:
    def handle_packet(self, pkt: bytes) -> None:
        pass

class TCPListenerSocket(TCPSocketBase):
    def __init__(self, local_addr: str, local_port: int,
            handle_new_client_func: callable, send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPListenerSocket:

        # These are all vars that are saved away for instantiation of TCPSocket
        # objects when new connections are created.
        self._local_addr = local_addr
        self._local_port = local_port
        self._handle_new_client = handle_new_client_func

        self._send_ip_packet_func = send_ip_packet_func
        self._notify_on_data_func = notify_on_data_func


    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & TCP_FLAGS_SYN:
            sock = TCPSocket(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport,
                    TCP_STATE_LISTEN,
                    send_ip_packet_func=self._send_ip_packet_func,
                    notify_on_data_func=self._notify_on_data_func)

            self._handle_new_client(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport, sock)

            sock.handle_packet(pkt)


class TCPSocket(TCPSocketBase):
    def __init__(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, state: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:

        # The local/remote address/port information associated with this
        # TCPConnection
        self._local_addr = local_addr
        self._local_port = local_port
        self._remote_addr = remote_addr
        self._remote_port = remote_port

        # The current state (TCP_STATE_LISTEN, TCP_STATE_CLOSED, etc.)
        self.state = state

        # Helpful methods for helping us send IP packets and
        # notifying the application that we have received data.
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        # Base sequence number
        self.base_seq_self = self.initialize_seq()

        # Base sequence number for the remote side
        self.base_seq_other = None


    @classmethod
    def connect(cls, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:
        sock = cls(local_addr, local_port,
                remote_addr, remote_port,
                TCP_STATE_CLOSED,
                send_ip_packet_func, notify_on_data_func)

        sock.initiate_connection()

        return sock


    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if self.state != TCP_STATE_ESTABLISHED:
            self.continue_connection(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            if data:
                # handle data
                self.handle_data(pkt)
            if tcp_hdr.flags & TCP_FLAGS_ACK:
                # handle ACK
                self.handle_ack(pkt)


    def initialize_seq(self) -> int:
        return random.randint(0, 65535)


    def initiate_connection(self) -> None:
        self.base_seq_self = self.initialize_seq()
        self.send_packet(self.base_seq_self, 0, TCP_FLAGS_SYN)
        self.state = TCP_STATE_SYN_SENT

    def handle_syn(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        
        if not tcp_hdr.flags & TCP_FLAGS_SYN:
            return
        
        self.base_seq_other = tcp_hdr.seq
        self.base_seq_self = self.initialize_seq()
        self.send_packet(self.base_seq_self, self.base_seq_other + 1, TCP_FLAGS_SYN | TCP_FLAGS_ACK)
        self.state = TCP_STATE_SYN_RECEIVED

    def handle_synack(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        
        if not (tcp_hdr.flags & TCP_FLAGS_SYN and tcp_hdr.flags & TCP_FLAGS_ACK):
            return
        if tcp_hdr.ack != self.base_seq_self + 1:
            return
        
        self.base_seq_other = tcp_hdr.seq
        self.send_packet(self.base_seq_self + 1, self.base_seq_other + 1, TCP_FLAGS_ACK)
        self.state = TCP_STATE_ESTABLISHED

    def handle_ack_after_synack(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        
        if tcp_hdr.flags & TCP_FLAGS_SYN or not tcp_hdr.flags & TCP_FLAGS_ACK:
            return
        if tcp_hdr.ack != self.base_seq_self + 1:
            return
        
        self.state = TCP_STATE_ESTABLISHED
    def continue_connection(self, pkt: bytes) -> None:
        if self.state == TCP_STATE_LISTEN:
            self.handle_syn(pkt)
        elif self.state == TCP_STATE_SYN_SENT:
            self.handle_synack(pkt)
        elif self.state == TCP_STATE_SYN_RECEIVED:
            self.handle_ack_after_synack(pkt)

    def send_data(self, data: bytes, flags: int=0) -> None:
        pass

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int,
            seq: int, ack: int, flags: int, data: bytes=b'') -> bytes:
        # Create IP header
        ip_header = IPv4Header(IP_HEADER_LEN + TCP_HEADER_LEN + len(data), 64, IPPROTO_TCP, 0, src, dst)
        
        # Create TCP header
        tcp_header = TCPHeader(sport, dport, seq, ack, flags, 0)
        
        # Combine headers and data
        return ip_header.to_bytes() + tcp_header.to_bytes() + data

    def send_packet(self, seq: int, ack: int, flags: int, data: bytes=b'') -> None:
        pkt = self.create_packet(self._local_addr, self._local_port,
                                 self._remote_addr, self._remote_port,
                                 seq, ack, flags, data)
        self._send_ip_packet(pkt)

    def handle_data(self, pkt: bytes) -> None:
        pass

    def handle_ack(self, pkt: bytes) -> None:
        pass
