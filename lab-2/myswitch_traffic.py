'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mac_table={}
    cnt=0

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return


        if eth.src not in mac_table or mac_table[eth.src][0]!=fromIface:
            if cnt>=5:
                del mac_table[min(mac_table,key=lambda i: mac_table[i][1])]
            else:
                cnt+=1
            mac_table[eth.src]=[fromIface,0]
        else:
            mac_table[eth.src][1]+=1

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        elif eth.dst in mac_table:
            if mac_table[eth.dst][0]!=fromIface:
                log_info (f"Sending packet {packet} to {mac_table[eth.dst][0]}")
                net.send_packet(mac_table[eth.dst][0], packet)
                mac_table[eth.dst][1]+=1
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)

    net.shutdown()
