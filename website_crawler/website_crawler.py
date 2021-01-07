#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              30 December 2020 
* Filename:             website_crawler.py
* Example Run (Linux):  python3 website_crawler.py -t altoromutual.com -s ./subdomain_list.txt -p ./pages_dirs_list.txt
"""

import argparse
import requests
import urllib.parse
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
    print("[+] If the target website is altoromutual.com and if the subdomain wordlist (subdomain_list.txt) and the wordlist for common web pages and directory names (pages_dirs_list.txt) are in the present working directory, then run the script as:")
    print("\tpython3 " + __file__ + " -t altoromutual.com -s ./subdomain_list.txt -p ./pages_dirs_list.txt")

""" 
* Function Name:  get_website_crawler_args()
* Input:          None
* Output:         args.target (string): Domain name of the target website to crawl.
*                 args.subdomain_list (string): Path to wordlist file containing common subdomains.
*                 args.pages_dirs_list (string): Path to wordlist file containing common file and directory names.
* Logic:          The function parses the parameters passed to the script and verifies if all the required parameters are present.
* Example Call:   target, subdomain_list, pages_dirs_list = get_code_injector_args()
"""
def get_website_crawler_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=str, help="Domain name of the target website to crawl (required)")                           
    parser.add_argument("-s", "--subdomain_list", type=str, help="Path to wordlist file containing common subdomains (required)")
    parser.add_argument("-p", "--pages_dirs_list", type=str, help="Path to wordlist file containing common file and directory names (required)")

    args = parser.parse_args()

    if((args.target == None) and (args.subdomain_list == None) and (args.pages_dirs_list == None)):
        print("\nError: Arguments missing!! Pass the target domain and the subdomain, pages and directories wordlists as an argument to the script.")
        print_sample_usage_msg()        

    elif(args.target == None):
        print("\nError: Target domain missing!! Pass the domain name of the target website to crawl as an argument to this script.")
        print_sample_usage_msg()

    elif(args.subdomain_list == None):
        print("\nError: Path to subdomain wordlist missing!! Pass the path to the wordlist file containing common subdomains as an argument to the script.")
        print_sample_usage_msg()

    elif(args.pages_dirs_list == None):
        print("\nError: Path to subdomain wordlist missing!! Pass the path to the wordlist file containing common web page and directory names as an argument to the script.")
        print_sample_usage_msg()

    return args.target, args.subdomain_list, args.pages_dirs_list

""" 
* Function Name:  remove_protocol()
* Input:          target (string): The target website to crawl.
* Output:         target (string): The target website to crawl with the protocol (HTTP / HTTPS) removed.
* Logic:          The function removes http:// or https:// from the start of target if it is present so that we can append the subdomain to the start of the domain name later. 
* Example Call:   target = remove_protocol("http://altoromutual.com")
"""
def remove_protocol(target):
    if(target[:7] == "http://"):
        target = target[7::]
        target = "".join(target)

    elif(target[:8] == "https://"):
        target = target[8::]
        target = "".join(target)

    return target

""" 
* Function Name:  get_target_root()
* Input:          target (string): The target website to crawl.
* Output:         target (string): Domain name of the target website to crawl.
* Logic:          The function changes the target to the index page of the website if in case the input target from the user points to any other page in the website.
* Example Call:   target = get_target_root("altoromutual.com/contact")
"""
def get_target_root(target):
    return target.split("/")[0]

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
* Function Name:  remove_existing_subdomain()
* Input:          target (string): The target website to crawl.
*                 subdomain_list (string): Path to wordlist file containing common subdomains.
* Output:         target (string): Domain name of the target website to crawl with the subdomain removed if it existed.
* Logic:          The function removes the subdomain if in case it is present in the input target from the user.
* Example Call:   target = remove_existing_subdomain("mail.altoromutual.com", "./subdomain_list.txt")
"""
def remove_existing_subdomain(target, subdomain_list):
    if(validate_ip(target) == 0):
        if(len(target.split(".")) > 2):
            probable_subdomain = target.split(".")[0]

            with open(subdomain_list, "r") as file:
                for line in file:
                    subdomain = line.strip()

                    if(probable_subdomain == subdomain):
                        target = target.split(".")[1::]
                        target = ".".join(target)
                        break

    return target

""" 
* Function Name:  find_links_with_wordlist()
* Input:          base_url (string): The base URL with subdomain.
*                 pages_dirs_list (string): Path to wordlist file containing common file and directory names.
* Output:         None
* Logic:          The function finds all the webpages that gives successful response when combining the target domain with the given wordlist elements.
* Example Call:   find_links_with_wordlist("mail.altoromutual.com", "./pages_dirs_list.txt")
"""
def find_links_with_wordlist(base_url, pages_dirs_list):
    global links
    global count
    global stop

    with open(pages_dirs_list, "r") as file:
        for line in file:
            page_dir = line.strip()
            url_path = base_url + page_dir

            try:
                response = requests.get(url_path)

                if(response.status_code == 200):
                    if(("#" not in url_path) and (url_path not in links)):
                        links.append(url_path)
                        count += 1
                        print("[+] " + url_path)

                        find_links_within_html(url_path, response.content)

            except KeyboardInterrupt:
                stop = 1
                break

            except:
                continue

""" 
* Function Name:  get_links_from()
* Input:          response_content (string): The content of the target webpage.
* Output:         href_links (list): List of all href links in the target page.
* Logic:          The function retrieves all the links from the target webpage using the 'a' tags in the webpage.
* Example Call:   href_links = get_links_from("<!DOCTYPE HTML> ...")
"""
def get_links_from(response_content):
    href_links = []
    
    def find_links(reg_exp):
        links = re.findall(reg_exp, response_content.decode('utf-8'))
        
        if(len(links) > 0):
            for link in links:
                href_links.append(link)


    find_links('(?:href=")(.*?)"')
    find_links("(?:href=')(.*?)'")

    return href_links

""" 
* Function Name:  find_links_within_html()
* Input:          base_url (string): The URL of the target webpage.
*                 response_content (string): The content of the target webpage.
* Output:         None
* Logic:          The function is used to find all the links in the target using the 'a' tags within each page in the target domain.
* Example Call:   find_links_within_html("mail.altoromutual.com", "<!DOCTYPE HTML> ...")
"""
def find_links_within_html(base_url, response_content):
    global target
    global count
    global stop

    try:
        href_links = get_links_from(response_content)
        
        if(len(href_links) > 0):
            for link in href_links:
                link = urllib.parse.urljoin(base_url, link)
                link = "http://" + remove_protocol(link)

                if((target in link) and ("#" not in link) and (link not in links)):
                    try:
                        response = requests.get(link)

                        if(response.status_code == 200):
                            links.append(link)
                            count += 1
                            print("[+] " + link)
                            
                            find_links_within_html(link, response.content)

                    except KeyboardInterrupt:
                        stop = 1
                        break

                    except:
                        continue
                        
    except KeyboardInterrupt:
        stop = 1
        pass


if __name__ == "__main__":
    try:
        stop = 0

        target, subdomain_list, pages_dirs_list = get_website_crawler_args()

        if((target != None) and (subdomain_list != None) and (pages_dirs_list != None)):
            target = remove_protocol(target)
            target = get_target_root(target)
            target = remove_existing_subdomain(target, subdomain_list)

            print("\nCrawling " + target + "...\n\n")

            links = []
            count = 0

            base_url = "http://" + target + "/"
            response = requests.get(base_url)

            if(response.status_code == 200):
                links.append(base_url)
                count += 1
                print("[+] " + base_url)

                find_links_within_html(base_url, response.content)
            
                if(stop == 0):
                    print("\n\nCrawling completed...")
                    print("Total links found till now: " + str(count))
                    print("\nLooking for additional links using wordlist...this might take some time...\n\n")

                    with open(subdomain_list, "r") as file:
                        for line in file:
                            if(stop == 0):
                                subdomain = line.strip()
                                base_url = "http://{}.{}/".format(subdomain, target)
                                response = requests.get(base_url)

                                if(response.status_code == 200):            
                                    find_links_with_wordlist(base_url, pages_dirs_list)

            else:
                print("\n\nUnable to connect with target. Check the target domain and try again...")
       
    except KeyboardInterrupt:
        pass

    finally:
        try:
            print("\n\nStopping crawl...")
            print("\nTotal links found: " + str(count) + "\n")

        except:
            pass