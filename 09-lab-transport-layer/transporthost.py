from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN
from host import Host
from mysocket import UDPSocket, TCPSocketBase

class TransportHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.socket_mapping_udp = {}
        self.socket_mapping_tcp = {}

    def handle_tcp(self, pkt: bytes) -> None:
        # Extract IP header
        ip_header = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        
        # Extract TCP header
        tcp_header = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        
        # Get source and destination IP and port
        src_ip = ip_header.src  # Already a string, no need to convert
        dst_ip = ip_header.dst  # Already a string, no need to convert
        src_port = tcp_header.sport
        dst_port = tcp_header.dport
        
        # Look for an open TCP socket corresponding to the 4-tuple
        socket_key = (dst_ip, dst_port, src_ip, src_port)
        
        if socket_key in self.socket_mapping_tcp:
            # If a 4-tuple mapping is found, call handle_packet() on that socket
            sock = self.socket_mapping_tcp[socket_key]
            sock.handle_packet(pkt)
        else:
            # Look for a listener socket with only local address and port
            listener_key = (dst_ip, dst_port, None, None)
            if listener_key in self.socket_mapping_tcp:
                # If a listener is found, call handle_packet() on that socket
                sock = self.socket_mapping_tcp[listener_key]
                sock.handle_packet(pkt)
            else:
                # If no mapping of either type is found, call no_socket_tcp()
                self.no_socket_tcp(pkt)



    def handle_udp(self, pkt: bytes) -> None:
        # Extract IP header
        ip_header = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        
        # Extract UDP header
        udp_header = UDPHeader.from_bytes(pkt[IP_HEADER_LEN:UDPIP_HEADER_LEN])
        
        # Get destination IP and port
        dst_ip = ip_binary_to_str(ip_header.dst)
        dst_port = udp_header.dport
        
        # Look for an open UDP socket corresponding to the destination address and port
        socket_key = (dst_ip, dst_port)
        
        if socket_key in self.socket_mapping_udp:
            # If a mapping is found, call handle_packet() on that socket
            sock = self.socket_mapping_udp[socket_key]
            sock.handle_packet(pkt)
        else:
            # If no mapping is found, call no_socket_udp()
            self.no_socket_udp(pkt)


    def install_socket_udp(self, local_addr: str, local_port: int,
            sock: UDPSocket) -> None:
        self.socket_mapping_udp[(local_addr, local_port)] = sock

    def install_listener_tcp(self, local_addr: str, local_port: int,
            sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, None, None)] = sock

    def install_socket_tcp(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, \
                remote_addr, remote_port)] = sock

    def no_socket_udp(self, pkt: bytes) -> None:
        pass

    def no_socket_tcp(self, pkt: bytes) -> None:
        pass
