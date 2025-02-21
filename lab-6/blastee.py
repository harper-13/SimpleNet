#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp="0.0.0.0",
            num="0"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp=IPv4Address(blasterIp)
        self.num=int(num)
        self.pkt_received=[]#packets received

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_info(f"I got a packet {packet}")
        if packet[0].ethertype!=EtherType.IPv4 or (packet[0].ethertype==EtherType.IPv4 and packet[IPv4].protocol != IPProtocol.UDP):
            return

        ack_pkt=Ethernet()+IPv4(protocol=IPProtocol.UDP)+UDP()
        ack_pkt[0].ethertype=EtherType.IPv4
        ack_pkt[0].src=EthAddr("20:00:00:00:00:01")
        ack_pkt[0].dst=EthAddr("40:00:00:00:00:02")

        ack_pkt[1].ttl=64
        ack_pkt[1].src=IPv4Address("192.168.200.1")
        ack_pkt[1].dst=self.blasterIp
          
        ack_pkt+=(packet[3].to_bytes()[0:4])#set sequence number   

        payload=packet[3].to_bytes()[6:]#set payload
        length=int.from_bytes((packet[3].to_bytes()[4:6]),"big")
        if length<8:
            payload+=(0).to_bytes(8-length,"big")
        ack_pkt+=payload[0:8]
 
        self.net.send_packet("blastee-eth0", ack_pkt)

        seq=int.from_bytes((packet[3].to_bytes()[0:4]),"big") 
        if self.pkt_received[seq]==0:
            self.pkt_received[seq]=1
            self.num-=1


    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        for i in range(self.num+1):
            self.pkt_received.append(0)
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            if self.num==0:
                log_info (f"All packsssets have been received.")
                break

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()