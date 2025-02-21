#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp=IPv4Address(blasteeIp)
        self.num=int(num)
        self.length=int(length)
        self.senderWindow=int(senderWindow)
        self.timeout=float(timeout)/1000.0
        self.recvTimeout=float(recvTimeout)/1000.0
        self.start_time=time.time()
        self.end_time=time.time()

        self.lhs=1
        self.rhs=1
        self.isAcked=[]#acked 
        self.isSent=[]#sent out
        self.time_cnt=time.time()

        self.reTX=0#number of retransmitted packets
        self.coarseTimeout=0#number of coarese time outs
        self.throughput=0
        self.goodput=0

        self.retransmit_idx=0
        self.isRetransmitting=False
        self.finish_flag=False
        self.pkt_has_sent=False# if this round has sent packets

    def if_finished(self):
        if self.lhs==self.num+1:
            self.finish_flag=True
            self.end_time=time.time()
            return True

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        if packet[0].ethertype!=EtherType.IPv4 or (packet[0].ethertype==EtherType.IPv4 and packet[1].protocol != IPProtocol.UDP):
            log_info (f"It is not a legal UDP Packet")
            self.handle_no_packet()
            return

        seq=int.from_bytes(packet[3].to_bytes()[0:4],"big")
        log_info (f"receive Ack {seq} from blastee")
        self.isAcked[seq]=1

        #check if task is finished
        self.if_finished()

        while self.isAcked[self.lhs]==1:
            #make sure LHS is no larger than RHS
            if self.lhs+1>self.rhs or self.lhs+1>self.num+1:
                break
            self.lhs+=1
            
            self.time_cnt=time.time()
            log_info (f"LHS increases to {self.lhs} and RHS is still {self.rhs}")
            if self.lhs==self.num+1:#once the task is finished
                break

        self.if_finished()
        self.handle_no_packet()
        return False

    def retransmit(self):
        for i in range(self.retransmit_idx+1, self.rhs):#find the foremost to ack packet and retransmit
            self.retransmit_idx=i#the last retransmitted packet's index
            if i==self.num+1:#packet is retransmitted last
                break
            if self.isAcked[i]==0:
                self.reTX+=1
                log_info (f"retransmit packet with sequence number {i}")
                self.isSent[i]=1
                self.throughput+=self.length               
                self.net.send_packet("blaster-eth0",self.process(i))#create packet and send
                self.pkt_has_sent=True
                break
            else:
                log_info (f"packet {i} needn't to be retransmitted")


    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        if self.if_finished():
            return True

        if self.pkt_has_sent:
            return False

        # Do other things here and send packet
        #timeout and need retransmit
        if (time.time()-self.time_cnt)>self.timeout and self.isRetransmitting==False:            
            #start of retransmitting
            log_info (f"coarse time out")
            self.coarseTimeout+=1
            self.isRetransmitting=True
            self.retransmit_idx=self.lhs-1

            if self.retransmit_idx<self.rhs-1:
                self.retransmit()
            if self.retransmit_idx>=self.rhs-1 or self.retransmit_idx>=self.num:#retransmission is finished
                self.isRetransmitting=False

        elif self.isRetransmitting==True:#still retransmit
            if self.retransmit_idx<self.rhs:
                self.retransmit()
            if self.retransmit_idx>=self.rhs-1 or self.retransmit_idx>=self.num:
                self.isRetransmitting=False

        #can send new packet
        if self.pkt_has_sent==False:
            self.send_new_packet()
        return False


    def send_new_packet(self):
        if self.rhs-self.lhs+1<=self.senderWindow and self.rhs<=self.num:
            if self.isSent[self.rhs]==0:
                if self.rhs==1:#start of task
                    self.start_time=time.time()
                log_info (f"Transmit packet with sequence num {self.rhs}")
                self.net.send_packet("blaster-eth0",self.process(self.rhs))
                self.isSent[self.rhs]=1
                self.goodput+=self.length
                self.throughput+=self.length                    
                
                self.pkt_has_sent=True

            if self.rhs+1-self.lhs<=self.senderWindow and self.rhs+1<=self.num+1:
                self.rhs+=1
                log_info (f"LHS is still {self.lhs} and RHS increased to {self.rhs}")

                

    def process(self, seqNum): 
        # Creating the headers for the packet
        pkt = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()

        pkt[0].ethertype=EtherType.IPv4
        pkt[0].src=EthAddr("10:00:00:00:00:01")
        pkt[0].dst=EthAddr("40:00:00:00:00:01")
       
        pkt[1].src=IPv4Address("192.168.100.1")
        pkt[1].dst=self.blasteeIp
        pkt[1].ttl=64

        pkt+=seqNum.to_bytes(4,"big")
        pkt+=self.length.to_bytes(2,"big")
        pkt+=(0).to_bytes(self.length,"big")
        return pkt


    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        self.isAcked = [0] *(self.num+3)
        self.isSent = [0] *(self.num+3)
        # for i in range(self.num+3):
        #     self.isAcked.append(0)
        #     self.isSent.append(0)
            
        while True:
            self.pkt_has_sent=False# if this round has sent pkts
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                if self.handle_no_packet():
                    break
                continue
            except Shutdown:
                break
            if self.handle_packet(recv):
                break
        self.shutdown()
        self.printMyInfo()

    def shutdown(self):
        self.net.shutdown()

    def printMyInfo(self):
        print("Total TX time:",self.end_time-self.start_time)
        print("Numbers of reTX:",self.reTX)
        print("Numbers of Coarse Timeouts:",self.coarseTimeout)
        print("Throughput(Bps):",self.throughput/(self.end_time-self.start_time))
        print("Goodput(Bps):",self.goodput/(self.end_time-self.start_time))        

def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()