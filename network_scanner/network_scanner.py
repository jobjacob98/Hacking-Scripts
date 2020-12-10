#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              30 November 2020 
* Filename:             network_scanner.py
* Example Run (Linux):  python3 network_scanner.py -t 192.168.1.1/24
"""

import argparse
import scapy.all as scapy

""" 
* Function Name:  print_sample_usage_msg()
* Input:          None
* Output:         None
* Logic:          The function just prints a message on how to run the script with the required arguments.
* Example Call:   print_sample_usage_msg()
"""
def print_sample_usage_msg():
    print("\nSAMPLE USAGE:")
    print("If the target IP range is 192.168.1.1/24, then run the script as:")
    print("python3 " + __file__ + " -t 192.168.1.1/24\n")

""" 
* Function Name:  get_network_scanner_args()
* Input:          None
* Output:         args.target (string): The target IP range to scan for devices.
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   ip_targets = get_network_scanner_args()
"""
def get_network_scanner_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-t", "--target", type=str, help="the target IP range to scan for devices (required)")

    args = parser.parse_args()
    
    if(args.target == None):
        print("\nError: IP targets missing!! Pass the target IP range as an argument to the script.")
        print_sample_usage_msg()

    return args.target

""" 
* Function Name:  validate_ip_range()
* Input:          ip_targets (string): The target IP range which should be validated before scanning.
* Output:         1 if the target IP range is valid or else 0  
* Logic:          The function checks whether the given IP range is valid or not by splitting and validating each part of the input.
* Example Call:   validate_ip_range("192.168.1.1/24")
"""
def validate_ip_range(ip_targets):
    ip, nid_bits = ip_targets.split("/")
    ip_parts = ip.split('.')

    if len(ip_parts) != 4:
        return 0
    else:
        for part in ip_parts:
            if(0 <= int(part) <= 255):
                continue
            else:
                return 0
                
    if(1 <= int(nid_bits) <= 31):
        return 1

    return 0

""" 
* Function Name:  scan()
* Input:          ip_targets (string): The target IP range to scan for devices.
* Output:         None
* Logic:          The function sends ARP requests and receives back packets from live devices with their IP and MAC address.
* Example Call:   scan("192.168.1.1/24")
"""
def scan(ip_targets):
    arp_request = scapy.ARP(pdst=ip_targets)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    replies = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print("\nScan COMPLETE.")
    print("\nRESULTS:")
    print("--------------------------------------------")
    print("IP\t\t\tMAC Address")
    print("--------------------------------------------")

    for reply in replies:
        print(reply[1].psrc + "\t\t" + reply[1].hwsrc)
    
    print("--------------------------------------------\n")


if __name__ == "__main__":
    ip_targets = get_network_scanner_args()

    if(ip_targets != None):
        valid_ip_targets = validate_ip_range(ip_targets)

        if(valid_ip_targets):
            scan(ip_targets)

        else:
            print("\nERROR: Invalid IP targets!! Please pass a valid target IP range.\n")