Introduction :

This is a packet sniffer script written in Python using the Scapy library. The script allows you to monitor network traffic and extract information about the source and destination IP addresses, MAC addresses, transport layer protocol, and payload.
Requirements :

    - Python 3
    - Scapy library

Usage :

    1- Clone the repository to your local machine.
    2- Open a terminal window and navigate to the repository's directory.
    3- Run the script by typing python packet_sniffer.py [interface]. 
    4- Replace [interface] with the name of the network interface that you want to monitor.
    5- The script will start sniffing packets and print out the extracted information for each packet.

Notes : 

    - The script only works for IPv4 packets.
    - Make sure to run the script with sufficient privileges to access network interfaces.
    - The script does not store packets, it only prints the extracted information to the console.
