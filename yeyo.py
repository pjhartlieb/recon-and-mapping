#!/usr/bin/python

############################################################
##
##		yeyo.py v0.0.1
##		
##		Quickly gather contacts for a target organization or
##		keyword.
##		
##		by pjhartlieb @ black lantern security group 
##
############################################################

#REFERENCE
# [1] http://www.blackhatlibrary.net/Security101_-_Blackhat_Techniques_-_Hacking_Tutorials_-_Vulnerability_Research_-_Security_Tools:General_disclaimer

#DISCLAIMER [1]

# This script violates the ToS for www.yatedo.com and may get you banned.  
# This script is intended for educational purposes only.  
# I will not be held liable for a third party's use (or mis-use) of this information in any way.  
# Readers, end-users, and downloaders of content are responsible for their own actions.  
# Readers, end-users, and downloaders of content agree not to use content provided for illegal actions.  
# Content is provided as an educational resource for security researchers and penetration testers.

import argparse
import mechanize
import re

#define and process commmand line options

def get_args():
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Query Yatedo for users in a specific organization and display the results in csv format')
    # Add arguments
    parser.add_argument(
        '-k', '--keyword', type=str, help='target keyword', required=True)
    parser.add_argument(
        '-p', '--proxy', type=str, help='proxy', required=False)
    parser.add_argument(
        '-s', '--sleep', type=str, help='sleep time', required=False, default='5')
    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    keyword = args.keyword
    proxy = args.proxy 
    sleeptime = args.sleep
    # Return all variable values
    return keyword, proxy, sleeptime

#validate keyword, proxy, and sleeptime

def validate(keyword, proxy, sleeptime):  
    # validate the keyword
    # ref: http://pythex.org/
    print '\n[*] validating arguments'
    match = re.search(r'^\w+(\s\w+)*$', keyword)
    # If-statement after search() tests if it succeeded
    if match:                      
        print '\n\t[*] keyword: ', match.group()
    else:
        print '\n[*] ERROR. Please provide a properly formatted keyword. (eg. walmart) (eg. burger king)\n'
        exit()

    # validate the proxy
    # ref: http://pythex.org/
    if proxy:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:\d{1,5}', proxy)
        # If-statement after search() tests if it succeeded
        if match:                      
            print '\n\t[*] proxy: ', match.group()
        else:
            print '\n[*] ERROR. Please format proxy correctly. ( eg. w.x.y.z:port# )\n'
            exit()

    # validate the sleeptime
    # ref: http://pythex.org/
    if sleeptime:
        match = re.search(r'^\d{1,8}$', sleeptime)
        # If-statement after search() tests if it succeeded
        if match:                      
            print '\n\t[*] sleeptime: ', match.group(), 's\n'
        else:
            print '\n[*] ERROR. Seriously? Please enter a reasonable sleeptime in seconds (s). ( eg. 60 )\n'
            exit()

if __name__ == "__main__":

	# Match return values from get_arguments()
	# and assign to their respective variables
    keyword, proxy, sleeptime = get_args()

    validate(keyword, proxy, sleeptime)

#request frontpage

##set user-agent

##set proxy

##retrieve frontpage and verify that the server is up

#submit search

##set form parameters

#verify and decode content

##extract links with targets and additional results

##extract the link to *all* public profiles tied to the keyword results and sleep

##retrive page with links and results for all public profiles

##parse out links to people *and* links to additional results pages.  Create arrays with unique arrays and unique results pages 
	
#retrieve and scrape data for the first page of results

##scrape title

##scrape name

##scrape role

##scrape location

##print suitable users found to date

#retrieve and scrape data from the other pages of results

##scrape title

##scrape name

##scrape role

##scrape location

##print suitable users found to date

##help file content












