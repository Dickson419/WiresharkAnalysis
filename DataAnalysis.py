"""Analysing and looking at captured protocols - turning off only_summaries will give more depth for analysis"""
import pyshark #wrapper for tshark
import collections #counter for doing maths
import matplotlib.pyplot as plt
import numpy as np #sort keys in graph

packet_count = 0
"""Read in pcap file"""
cap = pyshark.FileCapture('test.pcapng', only_summaries=False) #only_summaries to reduce amount of data
cap.load_packets()
protocol_list = []

for packet in cap:
    print(packet)
    line = str(packet)
    formattedLine = line.split(" ") #create a list of different headings i.e dst, src etc It is now iterable!
    protocol_list.append(formattedLine[0])
    packet_count += 1

print("List = ", formattedLine)

# counter = collections.Counter(protocol_list)
#
# plt.style.use('ggplot')
# y_pos = np.arange(len(list(counter.keys())))
# plt.bar(y_pos, list(counter.values()), align='center', alpha=0.5, color=['b','g','r','c','m'])
# plt.xticks(y_pos, list(counter.keys()))
# plt.ylabel('Frequency')
# plt.xlabel('Protocols')
# plt.show()
