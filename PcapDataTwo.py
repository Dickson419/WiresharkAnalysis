import pyshark

def network_conversation(packet):
    try:
        # Get the source IP address
        source_address = packet.ip.src
        # Get the destination IP address
        destination_address = packet.ip.dst
        # Return a tuple of source and destination IP addresses
        return (source_address, destination_address)
    except AttributeError as e:
        pass

# Open a pcap file named 'sample.pcap' and read the network traffic
capture = pyshark.FileCapture('pcap_sample1.pcapng')

# Create empty sets to store unique source and destination IP addresses
source_ips = set()
destination_ips = set()

# Iterate through each packet in the pcap file
for packet in capture:
    # Call the network_conversation function to extract source and destination IP addresses
    results = network_conversation(packet)
    # If the network_conversation function returned something (i.e. the packet contains the attributes we're looking for),
    # add the source and destination IP addresses to their respective sets
    if results is not None:
        source_ips.add(results[0])
        destination_ips.add(results[1])

# Print the unique source and destination IP addresses
print("Unique source IP addresses:")
for source_ip in source_ips:
    print(source_ip)

print("\nUnique destination IP addresses:")
for destination_ip in destination_ips:
    print(destination_ip)
