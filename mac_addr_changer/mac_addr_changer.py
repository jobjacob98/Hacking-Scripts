#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              26 November 2020 
* Filename:             mac_addr_changer.py
* Example Run (Linux):  python3 mac_addr_changer.py -i wlan0 -m 00:11:22:33:44:55 
"""

import argparse
import subprocess
import psutil
import re

""" 
* Function Name:  print_sample_usage_msg()
* Input:          None
* Output:         None
* Logic:          The function just prints a message on how to run the script with the required arguments.
* Example Call:   print_sample_usage_msg()
"""
def print_sample_usage_msg():
    print("\nSAMPLE USAGE:")
    print("If your interface is wlan0 and the new MAC address for wlan0 should be 00:11:22:33:44:55, then run the script as:")
    print("python3 " + __file__ + " -i wlan0 -m 00:11:22:33:44:55\n")

""" 
* Function Name:  get_mac_changer_args()
* Input:          None
* Output:         args.interface (string): The interface whose MAC address should be changed.
*                 args.mac (string): The new MAC address for the interface.
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   interface, new_mac = get_mac_changer_args()
"""
def get_mac_changer_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-i", "--interface", type=str, help="the interface whose MAC address should be changed (required)")
    parser.add_argument("-m", "--mac", type=str, help="the new MAC address for the interface (required)")

    args = parser.parse_args()

    if((args.interface == None) and (args.mac == None)):
        print("\nERROR: Interface and MAC address missing!! Pass the interface and the new MAC address as arguments to the script.")
        print_sample_usage_msg()
    
    elif(args.interface == None):
        print("\nError: Interface missing!! Pass the interface as an argument to the script.")
        print_sample_usage_msg()

    elif(args.mac == None):
        print("\nError: MAC address missing!! Pass the new MAC address as an argument to the script.")
        print_sample_usage_msg()

    return args.interface, args.mac

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
* Function Name:  validate_mac()
* Input:          mac (string): The MAC address that needs to be validated.
* Output:         1 if the MAC address is valid or else 0  
* Logic:          The function uses a regular expression to check whether the passed MAC address is valid or not.
* Example Call:   validate_mac("00:11:22:33:44:55")
"""
def validate_mac(mac):
    if(re.match("[0-9a-f]{2}([:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())):
        return 1
    else:
        return 0

""" 
* Function Name:  get_interface_mac_addr()
* Input:          interface (string): The interface whose MAC address should be retrieved.
* Output:         the MAC address if it exists or else None
* Logic:          The function uses a regular expression to search and retreive the MAC address of the interface from the output of the subprocess call.
* Example Call:   get_interface_mac_addr("wlan0")
"""
def get_interface_mac_addr(interface):
    ifconfig_interface_result = subprocess.check_output(["sudo", "ifconfig", interface])
    ifconfig_interface_mac = re.search("[0-9a-f]{2}([:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}", ifconfig_interface_result.decode('utf-8'))

    if(ifconfig_interface_mac == None):
        return None

    return ifconfig_interface_mac.group(0)

""" 
* Function Name:  change_mac_addr()
* Input:          interface (string): The interface whose MAC address should be changed.
*                 new_mac (string): The new MAC address for the interface.
* Output:         None
* Logic:          The function uses subprocessor calls to modify the MAC address of the given interface.
* Example Call:   change_mac_addr("wlan0", "00:11:22:33:44:55")
"""
def change_mac_addr(interface, new_mac):
    subprocess.call(["sudo", "ifconfig", interface, "down"])

    print("\nChanging MAC address of interface " + interface + " to " + new_mac + " ...")

    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    subprocess.call(["sudo", "ifconfig", interface, "up"])

    interface_mac_addr = get_interface_mac_addr(interface)

    if(interface_mac_addr == None):
        print("\nSorry, we were unable to change the MAC address of the given interface.")
        print("Check if the entered interface requires a MAC address.\n")

    elif(interface_mac_addr == new_mac):
        print("\nMAC address of interface " + interface + " changed SUCCESSFULLY :)\n")


if __name__ == "__main__":
    interface, new_mac = get_mac_changer_args()

    if((interface != None) and (new_mac != None)):
        valid_interface = validate_interface(interface)
        valid_mac = validate_mac(new_mac)

        if(valid_interface and valid_mac):
            change_mac_addr(interface, new_mac)

        else:
            if(not valid_interface):
                print("\nERROR: Invalid interface!! Please pass a valid interface.\n")
            elif(not valid_mac):
                print("\nERROR: Invalid MAC address!! Please pass a valid MAC address.\n")