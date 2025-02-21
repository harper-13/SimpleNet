#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.arp_table={}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp=packet.get_header(Arp)
        if arp is None:
            return 

        self.arp_table[arp.senderprotoaddr]=(arp.senderhwaddr,time.time())

        for ip,(mac,timestamp) in self.arp_table.items():
            print(ip,":",mac)
        print(" ")

        if arp.operation==1:#is arp request
            for iface in self.net.interfaces():
                if iface.ipaddr==arp.targetprotoaddr:
                    arp_reply=create_ip_arp_reply(iface.ethaddr,arp.senderhwaddr,iface.ipaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,arp_reply)
                    #print(type(ifaceName))

        cur=time.time()
        for ip,(mac,timestamp) in list(self.arp_table.items()):
            if cur-timestamp > 100:
                del self.arp_table[ip]


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

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
