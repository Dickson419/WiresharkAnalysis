import pyshark

"""
Define a function that takes a packet object as input, extracts information about the conversation,
and returns the conversation details as a string
"""
def network_conversation(packet):
  try:
    # Get the transport layer protocol (TCP, UDP, etc.)
    protocol = packet.transport_layer

    # Get the source IP address
    source_address = packet.ip.src

    # Get the source port number
    source_port = packet[packet.transport_layer].srcport

    # Get the destination IP address
    destination_address = packet.ip.dst

    # Get the destination port number
    destination_port = packet[packet.transport_layer].dstport

    # Return the conversation details as a string
    return (f'Protocol: {protocol} | Source Address: {source_address}  | Source Port:{source_port} --> \tDestination Address:{destination_address} | Destination Port:{destination_port}')

  # If any of the attributes we're trying to extract are not present in the packet, ignore the packet
  except AttributeError as e:
    pass

# Open a pcap file and read the network traffic
capture = pyshark.FileCapture('pcap_sample1.pcapng')

# Create an empty list to store the network conversations
conversations = []

# Iterate through each packet in the pcap file
for packet in capture:
  # Call the network_conversation function to extract conversation details
  results = network_conversation(packet)
  # If the network_conversation function returned something (i.e. the packet contains the attributes we're looking for),
  # add the conversation details to the list of conversations
  if results != None:
    conversations.append(results)

# Sort the list of conversations by protocol type (TCP first, then UDP), and print each conversation
for item in sorted(conversations):
  print (item)
