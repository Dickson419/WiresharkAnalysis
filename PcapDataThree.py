"""
A program to read in a pcap file and display source ip, destination ip and port numbers.
Network_conversation takes a line, or capture of a file, and extracts the relevant data ie src address.
A tuple is then returned and displayed.

Further analysis can be done to identify unknown ports. Such as Windows Terminal "netstat -ab".
"""

import pyshark

# Define a dictionary that maps port numbers to protocol names
port_lookup = {
    "20": "FTP - Data",
    "21": "FTP - Control",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "67": "DHCP - Server",
    "68": "DHCP - Client",
    "69": "TFTP",
    "80": "HTTP",
    "88": "Kerberos",
    "110": "POP3",
    "123": "NTP",
    "137": "NetBIOS - Name",
    "138": "NetBIOS - Datagram",
    "139": "NetBIOS - Session",
    "143": "IMAP",
    "161": "SNMP",
    "162": "SNMP - Trap",
    "179": "BGP",
    "443": "HTTPS",
    "445": "SMB",
    "465": "SMTPS",
    "500": "IKE",
    "514": "Syslog",
    "515": "LPD",
    "520": "RIP",
    "522": "NCP",
    "523": "NCP",
    "524": "NCP",
    "587": "SMTP",
    "623": "IPMI",
    "626": "Serial Bus Protocol 2 (SBP-2)",
    "631": "IPP",
    "636": "LDAPS",
    "873": "rsync",
    "902": "VMware Server Console",
    "989": "FTPS - Data",
    "990": "FTPS - Control",
    "993": "IMAPS",
    "995": "POP3S",
    "1433": "Microsoft SQL Server",
    "1521": "Oracle Database",
    "1723": "PPTP",
    "2049": "NFS",
    "2082": "cPanel",
    "2083": "cPanel - SSL",
    "2086": "WHM",
    "2087": "WHM - SSL",
    "2095": "cPanel Webmail",
    "2096": "cPanel Webmail - SSL",
    "2181": "ZooKeeper",
    "3128": "HTTP Proxy",
    "3306": "MySQL",
    "3389": "RDP",
    "3690": "SVN",
    "4333": "mSQL",
    "4848": "GlassFish Server",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "5984": "CouchDB",
    "6379": "Redis",
    "6667": "IRC",
    "7001": "WebLogic Server",
    "8080": "HTTP Proxy",
    "8086": "InfluxDB",
    "8088": "Radan HTTP",
    "8443": "HTTPS",
    "9000": "SonarQube",
    "9042": "Apache Cassandra",
    "9092": "Apache Kafka",
    "9200": "Elasticsearch",
    "9418": "Git",
    "9999": "OpenSSH",
    "27017": "MongoDB",
    "27018": "MongoDB",
    "27019": "MongoDB",
    "50000": "SAP Router",
    "50001": "SAP Router",
    "50013": "SAP Router",
}


def network_conversation(packet, port_lookup):
    try:
        # Get the protocol
        protocol = packet.transport_layer
        # Get the source IP address
        source_address = packet.ip.src
        # Get the source port
        source_port = str(packet[packet.transport_layer].srcport)
        # Get the destination IP address
        destination_address = packet.ip.dst
        # Get the destination port
        destination_port = str(packet[packet.transport_layer].dstport)
        # Look up the protocol names using the source and destination port numbers
        source_protocol_name = port_lookup.get(source_port, "Unknown")
        destination_protocol_name = port_lookup.get(destination_port, "Unknown")
        # Return a tuple of the source IP address, source port, destination IP address, destination port, and protocol names
        return (source_address, source_port, source_protocol_name, destination_address, destination_port, destination_protocol_name)
    except AttributeError as e:
        pass


capture = pyshark.FileCapture('pcap_sample1.pcapng')

# Create an empty list to store the conversations
conversations = []

# Iterate through each packet in the pcap file
for packet in capture:
    # Call the network_conversation function to extract the conversation details
    results = network_conversation(packet, port_lookup)
    # If the network_conversation function returned something (i.e. the packet contains the attributes we're looking for),
    # append the conversation details to the list
    if results is not None:
        conversations.append(results)

# Print the conversations
for conversation in conversations:
    print(f"{conversation[0]}:{conversation[1]} ({conversation[2]})--> {conversation[3]}:{conversation[4]} ({conversation[5]})")

