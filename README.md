

How the tool works:

1. The tool uses scapy library to sniff network packets.

2. The `packet_sniffer` function is called for each captured packet.

3. The function checks the packet's layers (e.g., IP, TCP, UDP, ICMP, Raw) and extracts relevant information.

4. The extracted information is printed to the console.

5. The `sniff` function is called with the ‘packet_sniffer` function as the callback and `store=False` to prevent storing the packets in memory.

_Important Notes:_

- [ ] This tool is for educational purposes only.
- [ ] Packet sniffing can be malicious if used without consent. 
- [ ] Always obtain explicit permission from network administrators and users before running a packet sniffer.
