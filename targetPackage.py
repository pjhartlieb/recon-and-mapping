#!/usr/bin/python

############################################################
#                                                          #
#    [-] Creating a target package and list operations     #
#                                                          #
#    [-] 2018.01.05                                        #
#          V0003                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#    [-] ACCOUNTS FOR UPPER AND LOWERCASE IN HOSTNAMES     #
#    [-] ACCOUNTS FOR UNALTERED ENTRIES                    #
#                                                          #
############################################################

import re
import csv
import time

# Final Snipe CSV template columns. This is the format for the int03.csv file below and
# the final output.

# IP                    [0]
# IP owner              [1]
# Protocol              [2]
# DNS Name              [3]
# Domain Owner          [4]
# CNAME/Redirect        [5]
# Translated Address    [6]
# PoC                   [7]
# Firewall policy       [8]
# Architecture          [9]
# Version Numbers       [10]
# Language              [11]
# Status                [12]
# Notes                 [13]
# Source                [14]
# Known Findings        [15]
# Risk                  [16]

# Intermediate Template_SnipeIT4.csv columns. This is the format for the file we are consuming.
# This is important for figuring out which entries(metadata) to overwrite

# Company [0]
# Asset Tag [1]
# Model [2]
# Category [3]
# Model No. [4]
# Manufacturer [5]
# Hostname [6]
# IP Address [7]
# Architecture [8]
# Language [9]
# Source [10]
# Known Findings [11]
# Risk [12]
# Version Number [13]
# General Notes [14]
# IP Address Owner [15]
# Domain Owner[16]
# Protocol[17]

# Import Template_SnipeIT4.csv as list
with open('snipe.csv', 'r') as f:
  reader = csv.reader(f)
  snipePackage = list(reader)
g = len(snipePackage)

# Import int03.csv as list
with open('int01.csv', 'r') as f:
  reader = csv.reader(f)
  currentPackage = list(reader)
h = len(currentPackage)

# Initialize global arrays
outlierEntries = []
newtargetPackage = []
outlierEntry = []


def findHost(hostname, snipeEntry):
    # Hunt for hostnames in the current target package (currentPackage). If a hostname match is found
    # overwrite the metadata in the current row from the target package with the data from the entry
    # being examined in Template_SnipeIT4.csv. This function returns a trigger for a match (trigger)
    # as well as the updated currentPackage. Its a mutable list so, currentPackage should carry each change
    # we make along with it. If the hostname is not found it will return a new entry for
    # the newly identified target.

    # This is the metadata from Template_SnipeIT4.csv. It will be used to overwrite data in
    # currentPackage when a match os found
    ipAddress = snipeEntry[7]
    architecture =snipeEntry[8]
    language = snipeEntry[9]
    source = snipeEntry[10]
    knownFindings = snipeEntry[11]
    risk = snipeEntry[12]
    versionNumber = snipeEntry[13]
    generalNotes = snipeEntry[14]
    ipaddressOwner = snipeEntry[15]
    domainOwner = snipeEntry[16]
    protocol = snipeEntry[17]

    trigger = 1 # when a match is found, this is toggled to "0"

    for idx, val in enumerate(currentPackage): # enumerate allows for editing list elements in place
        picker = currentPackage[idx][3]
        if hostname.lower() == picker.lower(): # look for hostname match in each row of currentPackage
            currentPackage[idx] = [ipAddress, ipaddressOwner, protocol, hostname, domainOwner, val[5], val[6], val[7], val[8],
                     architecture, versionNumber, language, val[12], generalNotes, source + ":" + val[14], knownFindings,
                     risk]
            trigger = 0
        else:
            currentPackage[idx] = val # if no match is found, leave the row as it was
    if trigger == 1: # Go create an entry for this entry that is missing in the current target package
        outLier = processoutlierEntries(hostname, snipeEntry)
    else:
        outLier = 0
    return currentPackage ,outLier


def processHost(targets):
    # Select the "hostname" from each row in the Template_SnipeIT4.csv file and look for a match.
    # This function will return a fresh target package (updatedPackage) that includes
    # updated rows for every match in the Template_SnipeIT4.csv file. Every time there is a match we
    # are taking the metadata from Template_SnipeIT4.csv and overwriting the placeholders
    # in the existing target package. It also returns the number of matches (matchCounter) and
    # a list containing newly generated entries for outLiers.

    matchCounter = 0
    for snipeEntry in targets:
        hostname = snipeEntry[6]
        updatedPackage, outLier = findHost(hostname, snipeEntry)

        if outLier != 0:                    # If an outLier entry is generated then append the entry
            outlierEntries.append(outLier)
        else:
            matchCounter = matchCounter+1

    return updatedPackage, matchCounter, outlierEntries # Return updated target list and new outLier entries


def processoutlierEntries(target, metaEntry):
    # Sort missed matches as an IP or a dns name
    # Generate entries for newly discovered hosts
    # Return new entry

    ipAddress = metaEntry[7]
    architecture =metaEntry[8]
    language = metaEntry[9]
    source = metaEntry[10]
    knownFindings = metaEntry[11]
    risk = metaEntry[12]
    versionNumber = metaEntry[13]
    generalNotes = metaEntry[14]
    ipaddressOwner = metaEntry[15]
    domainOwner = metaEntry[16]
    protocol = metaEntry[17]

    # Sort missed matches as an IP or a dns name
    match = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', target)
    if match:
        outlierEntry = [target, ipaddressOwner,protocol,"<dns_name>",domainOwner,
        "<CNAME_redirect>","<translated_addr>","<PoC>","<firewall_policy>",architecture,versionNumber,
                   language,"<status>",generalNotes,source,knownFindings,risk]
    else:
        outlierEntry = ["<IP>",ipaddressOwner,protocol,target,domainOwner,
        "<CNAME_redirect>","<translated_addr>","<PoC>","<firewall_policy>",architecture,versionNumber,
                   language,"<status>",generalNotes,source,knownFindings,risk]

    return outlierEntry


def glomPackage(entryMatches, orphanEntries):
    # Combine the new target package entries with the updated target package
    # Return the new target package
    for candidateOrphan in orphanEntries:
        newtargetPackage.append(candidateOrphan)
    for candidateEntry in entryMatches:
        newtargetPackage.append(candidateEntry)
    return newtargetPackage


def createpackageFile(targetPackagecsv):
    # Write the new target package to a file
    newtargetPackage = open('<date>_<name>.csv', 'w')
    with currenttargetPackage:
        writer = csv.writer(newtargetPackage)
        writer.writerows(targetPackagecsv)


def printStats(snipePackage, currentPackage, matches, missedMatches, newtargets):
    print ""
    print "[-] Analyzed " + str(len(currentPackage)) + " targets in the current target package \n"
    print "[-] Analyzed " + str(len(snipePackage)) + " candidate targets in the new resource file\n"
    print "[-] Found " + str(matches) + " matches in current target package \n"
    print "[-] Updated " + str(matches) + " entries in current target package \n"
    print "[-] Identified " + str(len(missedMatches)) + " resources not in the current target package \n"
    print "[-] Created new target package with " + str(len(newtargets)) + " entries \n"
    print "[-] Target package written to <date>_<name>.csv \n"


if __name__ == '__main__':
    freshPackage, matches, missedmatchEntries = processHost(snipePackage)
    targetPackage = glomPackage(freshPackage, missedmatchEntries)
    createpackageFile(targetPackage)
    printStats(snipePackage, currentPackage, matches, missedmatchEntries, targetPackage)
