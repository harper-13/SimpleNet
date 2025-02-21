#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.packet import *
from ipaddress import ip_network

last_arp_request_time = {}

class WaitingList:
    def __init__(self, packet, next_ip):
        self.packet = packet
        self.request_count = 0
        self.start_time = time.time()
        self.last_request_time = 0
        self.dst_ip = packet.get_header(IPv4).dst
        self.next_ip = next_ip

        if self.dst_ip not in last_arp_request_time:
            last_arp_request_time[self.dst_ip] = 0

    def needs_arp_request(self, current_time):
        return current_time - self.last_request_time > 1 and self.request_count < 4 and current_time - last_arp_request_time[self.dst_ip] > 1


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interface_ips = {intf.ipaddr: intf for intf in net.interfaces()}
        #print(self.interface_ips)
        self.interface_names = {intf.name: intf for intf in net.interfaces()}
        self.intf_ethaddr = {intf: intf.ethaddr for intf in net.interfaces()}
        self.ARPtable = {}
        self.waiting_packets = []
        self.forwarding_table = []
        self.build()

    def build(self):
        for intf in self.net.interfaces():
            network_address = ip_network(f"{intf.ipaddr}/{intf.netmask}", strict=False).network_address           
            entry = {
                'network address': network_address,
                'subnet address': IPv4Address(intf.netmask),
                'next_ip': None,
                'intf': intf.name
            }
            self.forwarding_table.append(entry)
        with open('forwarding_table.txt', 'r') as f:
            for line in f:
                network, mask, next_ip, intf_name = line.strip().split()
                network_address = network_address = ip_network(f"{network}/{mask}", strict=False).network_address
                entry = {
                    'network address': network_address,
                    'subnet address': IPv4Address(mask),
                    'next_ip': IPv4Address(next_ip) if next_ip != '-' else None,
                    'intf': intf_name
                }
                self.forwarding_table.append(entry)


    def handle_packet(self, recv):
        _, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        icmp = packet.get_header(ICMP)
        udp = packet.get_header(UDP)
        ip = packet.get_header(IPv4)
        if arp:
            if arp.operation == ArpOperation.Request:
                self.ARPtable[arp.senderprotoaddr] = arp.senderhwaddr
                #Handling arp request
                if arp.targetprotoaddr in self.interface_ips:
                    src_intf = self.interface_ips[arp.targetprotoaddr]
                    arp_reply = create_ip_arp_reply(src_intf.ethaddr, arp.senderhwaddr, src_intf.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply)
            elif arp.operation == ArpOperation.Reply:
                    if arp.senderhwaddr == "ff:ff:ff:ff:ff:ff":
                        return
                    self.ARPtable[arp.senderprotoaddr] = arp.senderhwaddr
                    for waiting_packet in self.waiting_packets[:]:
                        if waiting_packet.next_ip == arp.senderprotoaddr:
                            best_match = self.match(waiting_packet.packet.get_header(IPv4).dst)
                            if best_match:
                                self.forward(best_match, waiting_packet.packet)
                            self.waiting_packets.remove(waiting_packet)
        elif icmp or udp:
            #handle_ip_packet
            if ip.ttl >= 1:
                ip.ttl -= 1
            if ip.dst in self.interface_ips:
                if icmp and icmp.icmptype == ICMPType.EchoRequest:
                    #send icmp echo reply
                    ip_header = packet.get_header(IPv4)
                    icmp_header = packet.get_header(ICMP)

                    eth = Ethernet()
                    eth.src = self.interface_names[ifaceName].ethaddr
                    eth.dst = packet[Ethernet].src
                    eth.ethertype = EtherType.IPv4

                    ip = IPv4()
                    ip.src=ip_header.dst
                    ip.dst = ip_header.src
                    ip.protocol = IPProtocol.ICMP
                    ip.ttl = 64

                    icmp = ICMP()
                    icmp.icmptype = ICMPType.EchoReply
                    icmp.icmpcode = 0
                    icmp.icmpdata.sequence = icmp_header.icmpdata.sequence
                    icmp.icmpdata.identifier = icmp_header.icmpdata.identifier
                    icmp.icmpdata.data = icmp_header.icmpdata.data

                    reply_packet = eth + ip + icmp
                    best_match = self.match(ip_header.src)
                    if best_match is not None: 
                        self.forward(best_match, reply_packet)

                    return
                else:
                    self.send_icmp_error(ICMPType.DestinationUnreachable, ICMPCodeDestinationUnreachable.PortUnreachable, packet, ifaceName)
                    return
        
            best_match = self.match(ip.dst)
            if best_match is None:
                self.send_icmp_error(ICMPType.DestinationUnreachable, ICMPCodeDestinationUnreachable.NetworkUnreachable, packet, ifaceName)
                return
            if ip.ttl <= 1:
                self.send_icmp_error(ICMPType.TimeExceeded, ICMPCodeTimeExceeded.TTLExpired, packet, ifaceName)
                return
            if udp:
                pass       
            self.forward(best_match, packet)


    def forward(self, best_match, packet):
        if best_match is None:            
            return
        ip_header = packet.get_header(IPv4)
        if ip_header is None or ip_header.ttl <= 1:
            return

        interface_name = best_match['intf']
        next_ip = best_match['next_ip'] if best_match['next_ip'] is not None else ip_header.dst
        if next_ip in self.ARPtable:
            dest_mac = self.ARPtable[next_ip]
            ethernet_header = Ethernet(dst = dest_mac, src = self.net.interface_by_name(interface_name).ethaddr, ethertype = EtherType.IPv4)
            packet[0] = ethernet_header
            self.net.send_packet(interface_name, packet)
        else:
            #Mac is unknown
            wl = WaitingList(packet, next_ip)
            self.waiting_packets.append(wl)
            if wl.needs_arp_request(time.time()):
                last_arp_request_time[wl.dst_ip] = time.time()
                #send arp request
                arp_request = create_ip_arp_request(self.net.interface_by_name(interface_name).ethaddr, self.net.interface_by_name(interface_name).ipaddr, next_ip)
                self.net.send_packet(self.net.interface_by_name(interface_name).name, arp_request)


    def send_icmp_error(self, icmp_type, icmp_code, packet, error_iface):
        ip = packet.get_header(IPv4)
        icmp = packet.get_header(ICMP)
        if icmp and icmp.icmptype in {ICMPType.DestinationUnreachable, ICMPType.TimeExceeded}:
            #"Received an ICMP error message;  do not respond"
            return
        
        icmp_error = ICMP()
        icmp_error.icmptype = icmp_type
        icmp_error.icmpcode = icmp_code
        icmp_error.icmpdata.data = packet.get_header(IPv4).to_bytes()[:28]

        ip_error = IPv4()
        best_match = self.match(ip.src)
        if best_match is not None:
            intf_match=self.interface_names[best_match['intf']]
            ip_error.src = intf_match.ipaddr
            eth_src = intf_match.ethaddr
        else:
            try:
                ip_error.src = self.interface_names[error_iface].ipaddr
                eth_src = self.interface_names[error_iface].ethaddr
            except KeyError:
                if packet.get_header(Ethernet) is not None:
                    for iface in self.interface_names.values():
                        if iface.ethaddr == packet.get_header(Ethernet).dst:
                            ip_error.src = iface.ipaddr
                            eth_src = iface.ethaddr
                            break

        eth_error = Ethernet()
        eth_error.src = eth_src
        eth_error.dst = packet[Ethernet].src
        eth_error.ethertype = EtherType.IPv4

        ip_error.dst = ip.src
        ip_error.protocol = IPProtocol.ICMP
        ip_error.ttl = 64

        error_packet = eth_error + ip_error + icmp_error
        if best_match is not None:
            self.forward(best_match, error_packet)


    def get(self,recv):
        packet = recv.packet  # 获取数据包对象
        ip_header = packet.get_header(IPv4)  # 尝试获取IP层头部
        arp_header = packet.get_header(Arp)  # 尝试获取ARP层头部
        eth_header = packet.get_header(Ethernet)  # 尝试获取以太网层头部
        if ip_header:
            IP_dst = ip_header.dst
        elif arp_header:
            ARP_dst = arp_header.targetprotoaddr
        iface_ethaddr = self.intf_ethaddr[self.net.interface_by_name(recv[1])]
        if packet.has_header(Vlan):           
            pass
        elif (iface_ethaddr == eth_header.dst or eth_header.dst=="ff:ff:ff:ff:ff:ff") and ((ip_header) or (arp_header and ARP_dst in self.interface_ips)):
            #if the dstip of an ICMP error is one of the router's interfaces
            if ip_header and ip_header.dst in self.interface_ips:
                icmp = packet.get_header(ICMP)
                if icmp and icmp.icmptype in {ICMPType.DestinationUnreachable, ICMPType.TimeExceeded}:#ICMP error for router's own IP                  
                    pass
            #ICMP error forwarding where next_ip fails to match
            if ip_header and ip_header.protocol == IPProtocol.ICMP:
                icmp = packet.get_header(ICMP)
                if icmp and icmp.icmptype in {ICMPType.DestinationUnreachable, ICMPType.TimeExceeded}:
                    best_match = self.match(IP_dst)
                    if best_match is None:#No valid next_ip for ICMP error                      
                        pass   
            self.handle_packet(recv)
        else: #Drop packet          
            pass


    def wait_processing(self):
        for waiting_packet in self.waiting_packets[:]:
            current_time = time.time()
            if waiting_packet.request_count >= 4:
                removed_dst_ip = waiting_packet.dst_ip
                if waiting_packet.packet.has_header(ICMP):
                    icmp = waiting_packet.packet.get_header(ICMP)
                    if icmp.icmptype == ICMPType.EchoRequest:
                        self.send_icmp_error(ICMPType.DestinationUnreachable, ICMPCodeDestinationUnreachable.HostUnreachable, waiting_packet.packet, self.net.interface_by_name(self.match(waiting_packet.next_ip)['intf']))
                for wp in self.waiting_packets[:]:
                    if wp.dst_ip == removed_dst_ip:
                        self.waiting_packets.remove(wp)
                break
            if waiting_packet.needs_arp_request(current_time):
                #send_arp_request
                interface=self.net.interface_by_name(self.match(waiting_packet.next_ip)['intf'])
                arp_request = create_ip_arp_request(interface.ethaddr, interface.ipaddr, waiting_packet.next_ip)
                self.net.send_packet(interface.name, arp_request)

                waiting_packet.last_request_time = current_time
                waiting_packet.request_count += 1
                last_arp_request_time[waiting_packet.dst_ip] = current_time


    def match(self, dest_ip):
        best_match = None
        length = -1        
        for entry in self.forwarding_table:
            network = IPv4Network(f"{entry['network address']}/{entry['subnet address']}")
            if dest_ip in network and network.prefixlen > length:
                best_match = entry
                length = network.prefixlen
        return best_match


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet()
                self.get(recv)
            except NoPackets:
                self.wait_processing()
            except Shutdown:
                break
        self.stop()


    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
