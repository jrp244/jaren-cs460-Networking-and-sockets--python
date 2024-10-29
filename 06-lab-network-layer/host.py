#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import struct
import sys
import array

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable

# From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

# From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

# From /usr/include/linux/in.h:
IPPROTO_ICMP = 1 # Internet Control Message Protocol
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward: bool):
        super().__init__()
        self._ip_forward = ip_forward
        self.arp_table = {}
        self.packet_queue = {}
        self.forwarding_table = ForwardingTable()

    def _handle_frame(self, frame: bytes, intf: str) -> None:
        dst_mac = frame[:6]
        src_mac = frame[6:12]
        eth_type = int.from_bytes(frame[12:14], 'big')
        payload = frame[14:]

        if dst_mac == mac_str_to_binary(self.interface_info_single(intf)['address']) or dst_mac == b'\xff\xff\xff\xff\xff\xff':
            if eth_type == ETH_P_IP:
                self.handle_ip(payload, intf)
            elif eth_type == ETH_P_ARP:
                self.handle_arp(payload, intf)
        else:
            self.not_my_frame(frame, intf)

    def handle_ip(self, pkt: bytes, intf: str) -> None:
        version_ihl = pkt[0]
        protocol = pkt[9]
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        
        if dst_ip in self.ipv4_addresses(intf):
            if protocol == IPPROTO_ICMP:
                self.handle_icmp(pkt)
            elif protocol == IPPROTO_TCP:
                self.handle_tcp(pkt)
            elif protocol == IPPROTO_UDP:
                self.handle_udp(pkt)
        elif self._ip_forward:
            self.forward_packet(pkt)
        else:
            self.not_my_packet(pkt, intf)

    def handle_icmp(self, pkt: bytes) -> None:
        dst_ip = socket.inet_ntoa(pkt[16:20])
        if dst_ip in [self.ipv4_address_single(intf) for intf in self.interfaces()]:
            print(f"Received ICMP packet for me: {pkt}")
        elif self._ip_forward:
            self.forward_packet(pkt)

    def handle_tcp(self, pkt: bytes) -> None:
        src_port = int.from_bytes(pkt[20:22], 'big')
        dst_port = int.from_bytes(pkt[22:24], 'big')
        seq_num = int.from_bytes(pkt[24:28], 'big')
        ack_num = int.from_bytes(pkt[28:32], 'big')
        
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        
        print(f"Received TCP packet: src={src_ip}:{src_port}, dst={dst_ip}:{dst_port}, "
            f"seq={seq_num}, ack={ack_num}")

    def handle_udp(self, pkt: bytes) -> None:
        src_port = int.from_bytes(pkt[20:22], 'big')
        dst_port = int.from_bytes(pkt[22:24], 'big')
        length = int.from_bytes(pkt[24:26], 'big')
        
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        
        print(f"Received UDP packet: src={src_ip}:{src_port}, dst={dst_ip}:{dst_port}, "
            f"length={length}")

    def handle_arp(self, pkt: bytes, intf: str) -> None:
        arp_header = pkt[:28]
        opcode = int.from_bytes(arp_header[6:8], 'big')
        if opcode == ARPOP_REQUEST:
            self.handle_arp_request(pkt, intf)
        elif opcode == ARPOP_REPLY:
            self.handle_arp_response(pkt, intf)

    def handle_arp_response(self, pkt: bytes, intf: str) -> None:
        sender_ip = socket.inet_ntoa(pkt[28:32])
        sender_mac = pkt[22:28]
        self.arp_table[sender_ip] = sender_mac
        if sender_ip in self.packet_queue:
            for queued_pkt, queued_intf in self.packet_queue[sender_ip]:
                self.send_packet_on_int(queued_pkt, queued_intf, sender_ip)
            del self.packet_queue[sender_ip]

    def handle_arp_request(self, pkt: bytes, intf: str) -> None:
        print(f"ARP packet: {pkt.hex()}")
        if len(pkt) < 42:
            print(f"ARP packet too short: {len(pkt)} bytes")
          #  return

        try:
            target_ip = socket.inet_ntoa(pkt[38:42])
            sender_ip = socket.inet_ntoa(pkt[28:32])
            sender_mac = mac_binary_to_str(pkt[22:28])
            print(f"ARP Request: Sender IP: {sender_ip}, Sender MAC: {sender_mac}, Target IP: {target_ip}")

            if target_ip in self.ipv4_addresses(intf):
                print(f"Responding to ARP request for {target_ip} on interface {intf}")
                self.send_arp_reply(pkt, intf)
            elif self._ip_forward:
                print(f"Forwarding ARP request for {target_ip}")
                for out_intf in self.interfaces():
                    if out_intf != intf:
                        self.send_frame(pkt, out_intf)
            else:
                print(f"Ignoring ARP request for {target_ip}")
        except Exception as e:
            print(f"Error processing ARP packet: {e}")

    def send_arp_reply(self, request_pkt: bytes, intf: str) -> None:
        # Extract information from the request packet
        sender_mac = request_pkt[22:28]
        sender_ip = request_pkt[28:32]
        target_ip = request_pkt[38:42]

        # Prepare the reply
        my_mac = mac_str_to_binary(self.interface_info_single(intf)['address'])
        my_ip = socket.inet_aton(self.ipv4_address_single(intf))

        # Create ARP reply
        arp_reply = struct.pack('!HHBBH6s4s6s4s',
            ARPHRD_ETHER, ETH_P_IP, 6, 4, ARPOP_REPLY,
            my_mac, my_ip,
            sender_mac, sender_ip)

        # Create Ethernet frame
        frame = sender_mac + my_mac + ETH_P_ARP.to_bytes(2, 'big') + arp_reply

        # Send the frame
        self.send_frame(frame, intf)
        print(f"Sent ARP reply to {socket.inet_ntoa(sender_ip)} on interface {intf}")


    def send_packet_on_int(self, pkt: bytes, intf: str, next_hop: str) -> None:
        # Check if we have the MAC address for the next hop
        if next_hop in self.arp_table:
            # We have the MAC address, build and send the Ethernet frame
            dst_mac = self.arp_table[next_hop]
            src_mac = self.interface_info_single(intf)['address']
            frame = dst_mac + src_mac + ETH_P_IP.to_bytes(2, 'big') + pkt
            self.send_frame(frame, intf)
        else:
            # We don't have the MAC address, queue the packet and send ARP request
            if next_hop not in self.packet_queue:
                self.packet_queue[next_hop] = []
            self.packet_queue[next_hop].append((pkt, intf))
            
            # Create and send ARP request
            src_mac_info = self.interface_info_single(intf)['address']
             # Convert src_mac to binary if it's a string
            if isinstance(src_mac_info, str):
                src_mac = mac_str_to_binary(src_mac_info)
            else:
                src_mac = src_mac_info
            src_ip = socket.inet_aton(self.ipv4_address_single(intf))  # Convert IP to bytes
            target_ip_bytes = socket.inet_aton(next_hop)  # Convert target IP to bytes

            # Create ARP request
            arp_request = struct.pack('!HHBBH6s4s6s4s',
                ARPHRD_ETHER,
                ETH_P_IP,
                6,  # Hardware address length (Ethernet = 6 bytes)
                4,  # Protocol address length (IPv4 = 4 bytes)
                ARPOP_REQUEST,
                src_mac,  # Sender MAC address (should already be bytes)
                src_ip,   # Sender IP address (now in bytes)
                b'\x00\x00\x00\x00\x00\x00',  # Target MAC address (6 bytes of zeros)
                target_ip_bytes)  # Target IP address (now in bytes)

            # Create Ethernet frame
            frame = b'\xff\xff\xff\xff\xff\xff' + src_mac + ETH_P_ARP.to_bytes(2, 'big') + arp_request

            # Send the frame
            self.send_frame(frame, intf)



    def send_icmp_time_exceeded(self, original_pkt: bytes):
        src_ip = socket.inet_ntoa(original_pkt[12:16])
        icmp_type = 11  # Time Exceeded
        icmp_code = 0   # TTL expired in transit
        icmp_checksum = 0
        unused = 0
        icmp_payload = original_pkt[:28]  # Include IP header and first 8 bytes of original packet
        icmp_msg = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, unused) + icmp_payload
        
        icmp_checksum = self.calculate_checksum(icmp_msg)
        icmp_msg = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, unused) + icmp_payload
        
        ip_header = self.create_ip_header(src_ip, len(icmp_msg))
        
        self.send_packet(ip_header + icmp_msg)

    def calculate_checksum(self, msg: bytes) -> int:
        if len(msg) % 2 == 1:
            msg += b'\0'
        s = sum(array.array("H", msg))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    def send_packet(self, pkt: bytes) -> None:
        print(f'Attempting to send packet:\n{repr(pkt)}')

    def forward_packet(self, pkt: bytes) -> None:
        dst_ip = socket.inet_ntoa(pkt[16:20])
        next_hop, out_intf = self.get_next_hop(dst_ip)
        if next_hop and out_intf:
            ttl = pkt[8] - 1
            if ttl > 0:
                pkt = pkt[:8] + bytes([ttl]) + pkt[9:]
                self.send_packet_on_int(pkt, out_intf, next_hop)
            else:
                self.send_icmp_time_exceeded(pkt)

    def get_next_hop(self, dst_ip: str) -> tuple[str, str]:
        return self.forwarding_table.get_entry(dst_ip)

    def not_my_frame(self, frame: bytes, intf: str) -> None:
        dst_mac = mac_binary_to_str(frame[:6])
        src_mac = mac_binary_to_str(frame[6:12])
        eth_type = int.from_bytes(frame[12:14], 'big')
        print(f"Received frame not for me on interface {intf}: "
            f"src={src_mac}, dst={dst_mac}, type=0x{eth_type:04x}")

    def not_my_packet(self, pkt: bytes, intf: str) -> None:
        version_ihl = pkt[0]
        protocol = pkt[9]
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        print(f"Received IP packet not for me on interface {intf}: "
            f"src={src_ip}, dst={dst_ip}, protocol={protocol}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    Host(args.router).run()

if __name__ == '__main__':
    main()
