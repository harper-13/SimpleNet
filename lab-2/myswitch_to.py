'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mac_table={}

    while True:
        #clear the timeout mac
        for item in list(mac_table):
            if time.time()-mac_table[item][1]>10:
                del mac_table[item]
                log_info("delete an info")

        try:
            _, fromIface, packet = net.recv_packet()
            #fromIface:store the name from which packet is received
            #packet:data packet
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return

        #add infomation
        if eth.src not in mac_table or mac_table[eth.src][0]!=fromIface:
            mac_table[eth.src]=(fromIface,time.time())

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        elif eth.dst in mac_table:
            if mac_table[eth.dst][0]!=fromIface:
                log_info (f"Sending packet {packet} to {mac_table[eth.dst][0]}")
                net.send_packet(mac_table[eth.dst][0], packet)
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)

    net.shutdown()
