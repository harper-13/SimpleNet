import time
import switchyard
import json
from switchyard.lib.userlib import *
from ipaddress import ip_network
from switchyard.lib.packet import icmp
from switchyard.lib.packet.icmp import ICMPType, ICMP

last_arp_request_time = {}

class WaitingList:
    def __init__(self, packet, next_hop_ip):
        self.packet = packet
        self.next_hop_ip = next_hop_ip
        self.last_request_time = 0
        self.request_count = 0
        self.dst_ip=packet.get_header(IPv4).dst
        self.start_time = time.time()
        if self.dst_ip not in last_arp_request_time:
            last_arp_request_time[self.dst_ip] = 0

    def needs_arp_request(self, current_time):
        return current_time - self.last_request_time > 1 and self.request_count < 4 and current_time - last_arp_request_time[self.dst_ip] > 1
    
class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interface_ips = {intf.ipaddr: intf for intf in net.interfaces()}
        # 10.10.0.1 10.11.0.1 172.16.40.1 172.16.48.1 192.168.128.1 192.168.129.1
        self.interface_ethaddr={intf: intf.ethaddr for intf in net.interfaces()}
        self.ARPtable = {}
        self.waiting_packets = []
        self.build()

    def build(self):
        self.forwarding_table = []
        for intf in self.net.interfaces():
            network_address = ip_network(f"{intf.ipaddr}/{intf.netmask}", strict=False).network_address
            
            entry = {
                'network address': network_address,
                'subnet address': IPv4Address(intf.netmask),
                'next hop address': None,
                'interface': intf.name
            }
            self.forwarding_table.append(entry)
        with open('forwarding_table.txt', 'r') as f:
            for line in f:
                network, mask, next_hop, intf_name = line.strip().split()
                network_address = ip_network(f"{network}/{mask}", strict=False).network_address                
                entry = {
                    'network address': network_address,
                    'subnet address': IPv4Address(mask),
                    'next hop address': IPv4Address(next_hop) if next_hop != '-' else None,
                    'interface': intf_name
                }
                self.forwarding_table.append(entry)

    def handle_packet(self, recv):
        _, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        icmp=packet.get_header(ICMP)
        udp=packet.get_header(UDP)
        if arp:
            if arp.operation == ArpOperation.Request:
                self.ARPtable[arp.senderprotoaddr] = arp.senderhwaddr
                #handle_arp_request
                if arp.targetprotoaddr in self.interface_ips:
                    src_intf = self.interface_ips[arp.targetprotoaddr]
                    arp_reply = create_ip_arp_reply(src_intf.ethaddr, arp.senderhwaddr, src_intf.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply)

            elif arp.operation == ArpOperation.Reply:
                if arp.senderhwaddr == "ff:ff:ff:ff:ff:ff":
                    return
                self.ARPtable[arp.senderprotoaddr] = arp.senderhwaddr
                #handle_arp_reply
                for waiting_packet in self.waiting_packets[:]:
                    if waiting_packet.next_hop_ip == arp.senderprotoaddr:
                        #match
                        best_match = None
                        max_prefix_length = -1
                        for entry in self.forwarding_table:
                            network = IPv4Network(f"{entry['network address']}/{entry['subnet address']}")
                            if waiting_packet.packet.get_header(IPv4).dst in network and network.prefixlen > max_prefix_length:
                                best_match = entry
                                max_prefix_length = network.prefixlen
                
                        if best_match:
                            self.forward_packet(best_match, waiting_packet.packet)
                        self.waiting_packets.remove(waiting_packet)

        elif icmp or udp:
            #handle_ip_packet
            ip_header = packet.get_header(IPv4)
            ip_header.ttl-=1
            if ip_header is None or ip_header.dst in self.interface_ips:
                return
            if 14+packet[IPv4].total_length!=packet.size():
                return
            #match
            best_match = None
            max_prefix_length = -1
            for entry in self.forwarding_table:
                network = IPv4Network(f"{entry['network address']}/{entry['subnet address']}")
                if ip_header.dst in network and network.prefixlen > max_prefix_length:
                    best_match = entry
                    max_prefix_length = network.prefixlen
            if best_match is not None:
                self.forward_packet(best_match, packet)

    def forward_packet(self, match, packet):
        if match is None:
            return
        ip_header = packet.get_header(IPv4)
        if ip_header is None:
            return 
        if ip_header.ttl <= 1:
            return  
        interface_name = match['interface']
        next_hop_ip = match['next hop address'] if match['next hop address'] is not None else ip_header.dst
        if next_hop_ip in self.ARPtable:
            dest_mac = self.ARPtable[next_hop_ip]
            ethernet_header = Ethernet(dst=dest_mac, src=self.net.interface_by_name(interface_name).ethaddr, ethertype=EtherType.IPv4)
            packet[0] = ethernet_header 
            self.net.send_packet(interface_name, packet)
        else:
            # MAC is unknown
            wl=WaitingList(packet, next_hop_ip)
            self.waiting_packets.append(wl)
            if wl.needs_arp_request(time.time()):
                last_arp_request_time[wl.dst_ip] = time.time()
                #send_arp_request
                interface=self.net.interface_by_name(interface_name)
                arp_request = create_ip_arp_request(interface.ethaddr, interface.ipaddr, next_hop_ip)
                self.net.send_packet(interface.name, arp_request)

    def get(self,recv):
        packet = recv.packet  # 获取数据包对象
        ip_header = packet.get_header(IPv4)  # 尝试获取IP层头部
        arp_header = packet.get_header(Arp)  # 尝试获取ARP层头部
        if arp_header:
            ARPdst_ip = arp_header.targetprotoaddr  # 获取ARP层的目标IP地址
        eth_header = packet.get_header(Ethernet)  # 尝试获取以太网层头部
        iface_ethaddr=self.interface_ethaddr[self.net.interface_by_name(recv[1])]
        if packet.has_header(Vlan):
            pass
        elif (iface_ethaddr == eth_header.dst or eth_header.dst=="ff:ff:ff:ff:ff:ff") and ((ip_header) or (arp_header and ARPdst_ip in self.interface_ips)):
            self.handle_packet(recv)

    def wait_processing(self):
        #processing waiting_packets
        for waiting_packet in self.waiting_packets[:]:
            current_time = time.time()
            if waiting_packet.request_count >= 4:
                removed_dst_ip = waiting_packet.dst_ip
                for wp in self.waiting_packets[:]:
                    if wp.dst_ip == removed_dst_ip:
                        self.waiting_packets.remove(wp)
                break
            if waiting_packet.needs_arp_request(current_time):

                best_match = None
                max_prefix_length = -1
                for entry in self.forwarding_table:
                    network = IPv4Network(f"{entry['network address']}/{entry['subnet address']}")
                    if waiting_packet.next_hop_ip in network and network.prefixlen > max_prefix_length:
                        best_match = entry
                        max_prefix_length = network.prefixlen

                #send_arp_request
                interface=self.net.interface_by_name(best_match['interface'])
                arp_request = create_ip_arp_request(interface.ethaddr, interface.ipaddr, waiting_packet.next_hop_ip)
                self.net.send_packet(interface.name, arp_request)

                waiting_packet.last_request_time = current_time
                waiting_packet.request_count += 1
                last_arp_request_time[waiting_packet.dst_ip] = current_time

    def start(self):
        while True:
            try:
                recv = self.net.recv_packet()
                self.get(recv)
            except NoPackets:
                self.wait_processing()
            except Shutdown:
                break
                
    def stop(self):
        self.net.shutdown()

def main(net):
    router = Router(net)
    router.start()