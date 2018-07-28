#!/usr/bin/python

############################################################
#                                                          #
#                                                          #
#    [-] Processing censys output                          #
#                                                          #
#    [-] 2017.12.28                                        #
#          V0001                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################

"""
This utility will process results from queries to the censys.io API and create csv output

Sample query:

python censys_io.py --api_id <api_id> --api_secret <secret>
                           443.https.tls.certificate.parsed.subject.common_name:/<regex>/ >> <output>.txt

[REF] https://github.com/gelim/censys/blob/master/censys_io.py
"""


import re
import argparse
import os
from colorama import init, Fore, Back, Style


def readData(resultsFile):
    """
    Read in the Censys results file

    Parameters
    ----------
    resultsFile: Search results returned by Censys as plain text

    Returns
    -------
    dataEntries (list)
    """
    with open(resultsFile, 'rb') as f:
        dataEntries = f.read().splitlines()
    return dataEntries

def proc(dataEntries):
    """
    Process Censys results and extract data

    Parameters
    ----------
    dataEntries: List containing Censys search results

    Returns
    -------
    streams (list)
    """
    streams = []

    for datum in dataEntries:

        # extract ip address
        match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', datum)
        if match:
            ipAddr = match.group(0)
        else:
            ipAddr = "<null>"

        # extract domain or subdomain
        match = re.search('SSL\: [A-Za-z0-9\.\*\+ ]* ', datum)
        if match:
            blob = match.group(0)
            match = re.search('([A-Za-z0-9\.\-]{1,}){1,5} ', blob)

            if match:
                fqdn = match.group(0)
            else:
                fqdn = "<null>"
        else:
            fqdn = "<null>"

        # extract ASN
        match = re.search('\([0-9]{1,}\)', datum)
        if match:
            blob = match.group(0)
            match = re.search('[0-9]{1,}', blob)

            if match:
                ASN = match.group(0)
            else:
                ASN = "<null>"
        else:
            ASN= "<null>"

        # extract protocols
        match = re.search('Tags\: ([A-Za-z0-9\-\, ]{1,}){1,}$', datum)
        if match:
            blob = match.group(0)
            match = re.search('([A-Za-z0-9\-\, ]{1,}){1,}$', blob)

            if match:
                protocols = match.group(0)
                protocols=protocols.strip()
                protocols = protocols.replace(',', '')
            else:
                protocols = "<null>"
        else:
            protocols = "<null>"


        stream = [fqdn, ipAddr, ASN, protocols]           # create and append list entry
        streams.append(stream)

    return streams

def writeResults(seeds):
    """
    Write results to screen

    Parameters
    ----------
    seeds: List containing Censys search results. Each entry has the data extracted by "proc"

    Returns
    -------
    N/A
    """
    for entry in streams:
        print str(entry[0]) + "," + str(entry[1]) + "," + str(entry[2]) + "," + str(entry[3])


def is_valid_file(parser, arg):         # verify that log file exists
    """
    Check if arg is a valid file that already exists on the file system.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg


def get_args():
    """
    Accept and retrieve filename for Censys results

    Parameters
    ----------
    N/A

    Returns
    -------
    resultsFile
    """

    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Parse raw Censys data')

    # Add arguments
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-f', '--file',
                        dest="filename",
                        type=lambda x: is_valid_file(parser, x),
                        help='raw Censys file',
                        required=True,
                        metavar='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    # Assign args to variables
    resultsFile = args.filename

    # Return all variable values
    return resultsFile

if __name__ == '__main__':
    resultsFile = get_args()
    dataEntries = readData(resultsFile)
    streams = proc(dataEntries)
    writeResults(streams)
