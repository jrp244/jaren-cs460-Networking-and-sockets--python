#!/usr/bin/python3

import asyncio
import struct
import time
from cougarnet.sim.host import BaseHost

def bytes_to_hex(byte_array, x, y=None):
    extractedBytes = byte_array[x:y]
    hexRep = extractedBytes.hex()
    return hexRep

def add_vlan_tag(frame, vlan_id):
    destMac = frame[0:6]
    srcMac = frame[6:12]
    etherType = frame[12:14]
    payload = frame[14:]

    _802 = b'\x81\x00'
    zeros = b'\x00'
    vlanIdBits = vlan_id.to_bytes(2, byteorder='big')
    vlanHeader = _802 + zeros + vlanIdBits
    new_frame = destMac + srcMac + vlanHeader + etherType + payload
    return new_frame

def remove_vlan_tag(byteArray):
    return byteArray[:12] + byteArray[16:]

class Switch(BaseHost):
    def __init__(self):
        super().__init__()
        self.mac_table = {}  # MAC address table
        self.aging_time = 8  # 8 seconds aging time

    def _handle_frame(self, frame: bytes, intf: str) -> None:
        dst_mac = frame[:6]
        src_mac = frame[6:12]
        
        # Update MAC table
        self.mac_table[src_mac] = (intf, time.time())
        
        # Handle VLANs
        vlan_id = self.int_to_vlan.get(intf, 0)
        if self.is_trunk_link(intf):
            if frame[12:14] == b'\x81\x00':  # 802.1Q VLAN tag
                vlan_id = struct.unpack('!H', frame[14:16])[0] & 0x0FFF
                frame = remove_vlan_tag(frame)

        # Determine outgoing interfaces
        if dst_mac == b'\xff\xff\xff\xff\xff\xff':  # Broadcast
            self._flood_frame(frame, intf, vlan_id)
        elif dst_mac in self.mac_table:
            out_intf, _ = self.mac_table[dst_mac]
            if self.int_to_vlan.get(out_intf, 0) == vlan_id or self.is_trunk_link(out_intf):
                self._send_frame(frame, out_intf, vlan_id)
        else:  # Unknown unicast
            self._flood_frame(frame, intf, vlan_id)

    def _flood_frame(self, frame, in_intf, vlan_id):
        for out_intf in self.interfaces:
            if out_intf != in_intf:
                if vlan_id == 0 or self.int_to_vlan.get(out_intf, 0) == vlan_id or self.is_trunk_link(out_intf):
                    self._send_frame(frame, out_intf, vlan_id)

    def _send_frame(self, frame, out_intf, vlan_id):
        if self.is_trunk_link(out_intf):
            frame = add_vlan_tag(frame, vlan_id)
        self.send_frame(frame, out_intf)

    async def _clean_mac_table(self):
        while True:
            current_time = time.time()
            expired = [mac for mac, (_, timestamp) in self.mac_table.items()
                       if current_time - timestamp > self.aging_time]
            for mac in expired:
                del self.mac_table[mac]
            await asyncio.sleep(1)  # Check every second

    def run(self):
        asyncio.get_event_loop().create_task(self._clean_mac_table())
        super().run()

def main():
    switch = Switch()
    switch.run()

if __name__ == '__main__':
    main()
