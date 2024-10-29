#!/usr/bin/env python3

import asyncio
import json
import socket
import time

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.sim.host import BaseHost

from prefix import *
from forwarding_table_native import ForwardingTableNative as ForwardingTable

class DVRouter(BaseHost):
    def __init__(self):
        super().__init__()
        self.my_dv = {}
        self.neighbor_dvs = {}
        self.neighbor_last_received = {}
        self.forwarding_table = ForwardingTable()
        self._initialize_dv_sock()

        # Initialize DV with local interfaces
        for intf in self.interfaces():
            ip = self.ipv4_address_single(intf)
            self.my_dv[f"{ip}/32"] = 0


    def _initialize_dv_sock(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('0.0.0.0', DV_PORT))

    def bcast_for_int(self, intf: str) -> str:
        obj = self.ipv4_address_info_single(intf)
        ip_int = ip_str_to_int(obj['address'])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, obj['prefixlen'])
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, obj['prefixlen'])
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

    def init_dv(self):
        loop = asyncio.get_event_loop()
        loop.add_reader(self.sock, self._handle_msg, self.sock)
        self.update_dv()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)
        loop.call_later(DV_TABLE_SEND_INTERVAL - DV_TABLE_SEND_INTERVAL / 2,
                self.update_dv_next)

    def _handle_msg(self, sock: socket.socket) -> None:
        data, addrinfo = sock.recvfrom(65536)
        self.handle_dv_message(data)

    def _send_msg(self, msg: bytes, dst: str) -> None:
        self.sock.sendto(msg, (dst, DV_PORT))

    def handle_dv_message(self, msg: bytes) -> None:
        dv_data = json.loads(msg.decode('utf-8'))
        sender_ip = dv_data['ip']
        sender_name = dv_data['name']
        sender_dv = dv_data['dv']

        if sender_name == self.hostname:
            return

        self.neighbor_dvs[sender_name] = sender_dv
        self.neighbor_last_received[sender_name] = time.time()
        self.update_dv()


    def send_dv_next(self):
        self.send_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def update_dv_next(self):
        self.update_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.update_dv_next)

    def handle_down_link(self, neighbor: str):
        self.log(f'Link down: {neighbor}')
        if neighbor in self.neighbor_dvs:
            del self.neighbor_dvs[neighbor]
        if neighbor in self.neighbor_last_received:
            del self.neighbor_last_received[neighbor]
        self.update_dv()


    def update_dv(self) -> None:
        old_dv = self.my_dv.copy()
        self.my_dv = {prefix: 0 for prefix in self.my_dv if self.my_dv[prefix] == 0}

        for neighbor, dv in self.neighbor_dvs.items():
            for dst, distance in dv.items():
                new_distance = distance + 1
                if dst not in self.my_dv or new_distance < self.my_dv[dst]:
                    self.my_dv[dst] = new_distance

        if self.my_dv != old_dv:
            self.update_forwarding_table()

    def update_forwarding_table(self):
        self.forwarding_table.flush()
        for dst, distance in self.my_dv.items():
            if distance > 0:
                next_hop = self.get_next_hop(dst)
                if next_hop:
                    self.forwarding_table.add_entry(dst, None, next_hop)


    def get_next_hop(self, dst):
        min_distance = float('inf')
        next_hop = None
        for neighbor, dv in self.neighbor_dvs.items():
            if dst in dv and dv[dst] < min_distance:
                min_distance = dv[dst]
                next_hop = neighbor
        return next_hop

    def send_dv(self) -> None:
        for intf in self.interfaces():
            src_ip = self.ipv4_address_single(intf)
            bcast_addr = self.bcast_for_int(intf)
            dv_msg = {
                'ip': src_ip,
                'name': self.hostname,
                'dv': self.my_dv
            }
            msg = json.dumps(dv_msg).encode('utf-8')
            self._send_msg(msg, bcast_addr)


def main():
    router = DVRouter()
    router.init_dv()
    router.run()

if __name__ == '__main__':
    main()
