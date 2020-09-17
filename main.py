"""
This script removes telnet traffic from a pcap file.
"""

from scapy.all import rdpcap, wrpcap

FILENAME = "traffic.pcap"
OUTFILE = "mod.pcap"
# read pcap file
pkts = rdpcap(FILENAME)

k = 0  # count removed packets
packet_list = []
for i in range(0, len(pkts)):
    paket = pkts[i]
    # filter by source and destination port
    if not (paket.haslayer("TCP") and paket.dport == 23 or paket.haslayer("TCP") and paket.sport == 23):
        packet_list.append(paket)
    else:
        k = k + 1
wrpcap(OUTFILE, packet_list)
print("Saved " + OUTFILE + " - removed " + str(k) + " telnet packets")
