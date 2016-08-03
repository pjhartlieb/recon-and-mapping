#!/usr/bin/python

############################################################
##
##		proxget.py v0.0.1
##		
##		Proxy-based document retrieval. An excuse to learn python and urllib2
##		
##		by pjhartlieb @ black lantern security group 
##
############################################################

# REFERENCE
# [1] http://www.blackhatlibrary.net/Security101_-_Blackhat_Techniques_-_Hacking_Tutorials_-_Vulnerability_Research_-_Security_Tools:General_disclaimer

# DISCLAIMER [1]

# This script is intended for educational purposes only.  
# I will not be held liable for a third party's use (or mis-use) of this information in any way.  
# Readers, end-users, and downloaders of content are responsible for their own actions.  
# Readers, end-users, and downloaders of content agree not to use content provided for illegal actions.  
# Content is provided as an educational resource for security researchers and penetration testers.

import sys, getopt
import urllib2
import socket
import errno
import os
import ssl
import re
from termcolor import colored

def file_ingest( url_list_file ): 
	#parses file containing list of URLs and returns a list
	##write URLs to a python list
	with open(url_list_file, 'r') as infile:
		data = infile.read()
	urlList = data.splitlines()
	return urlList;

def proxy_ingest( proxy_list_file ):
	#parses file containing list of proxys and returns a list
	##write proxys to a python list
	with open(proxy_list_file, 'r') as infile:
		data = infile.read()
	proxyList = data.splitlines()
	return proxyList;

def proxy_test ( protocol, proxy_candidate ): 
	#tests a candidate proxy from list and returns a list of hot proxies
	##build request
	returnCode=None
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	test_url = "https://www.stackoverflow.com" #test website

	if protocol == 'https': #build https request
		##create ssl context
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		##create request object
		request = urllib2.Request(test_url)
		##add header
		request.add_header('User-Agent', user_agent)
		##create opener(s)
		proxy_handler = urllib2.ProxyHandler({'https': proxy_candidate})
		##add ssl context to opener
		opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx), proxy_handler)
		##install opener. once installed all https requests will utilize opener
		urllib2.install_opener(opener)
	else: #build http request
		##create request object
		request = urllib2.Request(test_url)
		##add header
		request.add_header('User-Agent', user_agent)
		##create opener(s)
		proxy_handler = urllib2.ProxyHandler({'http': proxy_candidate})
		##add ssl context to opener
		opener = urllib2.build_opener(proxy_handler)
		##install opener. once installed all https requests will utilize opener
		urllib2.install_opener(opener)
	#make request
	try: 
		testResult = urllib2.urlopen(request, timeout=12)			
	except urllib2.URLError, e: #handle exception and provide reason or code
		if hasattr(e, 'reason'):
			print '\t\t---ERROR--- server could not be reached'
			#print '\t\tReason:',e.reason
		elif hasattr(e, code):
			print '\t\t---ERROR--- server could not handle request'
			#print '\t\tError code:',e.code
		else:
			print '\t\t---ERROR--- unknown error'
		pass
	except Exception, e: #handle all other exceptions
		print '\t\t---ERROR--- unknown error',e
		pass
	else:
		returnCode=testResult.getcode()
	#examine return code and return test results
	if returnCode == 200:
		return proxy_candidate;
	else:
		return;

def select_proxy ( candidate_proxies ):
	#select one candidate from the array
	##verify that there is at least one candidate in the array
	##select candidate from raw array
	##remove candidate from array
	##send candidate and remaining candidate array (proxyPool) back to caller
	selectProxy = None
	#localPool = candidate_proxies
	if len(candidate_proxies) >= 1:
		selectProxy = candidate_proxies.pop(0)
		proxyPool = candidate_proxies
	else:
		print '\t\t---ERROR--- no more proxies to select from'
		proxyPool = None
		print
	return selectProxy,proxyPool;

def find_proxy ( protocol, raw_proxy_list ):
	#continue to submit and test proxies until a hot proxy is found
	#once found return the hot proxy and the remaining candidates to the caller
	hotProxy=None
	##this prevents the function(s) from modifying the original proxyList
	proxyPool=raw_proxy_list[:]
	##check to see if a hotProxy has been found or if there are no more candidates
	while hotProxy == None and len(proxyPool) != 0:
		selectProxy, proxyPool = select_proxy(proxyPool)
		print '\t\t... trying %s' %selectProxy
		hotProxy = proxy_test(protocol, selectProxy)
	else:
		if hotProxy != None:
			print '\t\t---ALIVE--- %s' %hotProxy
	return hotProxy

def grab( url, proxy, protocol ): 
	#retrieves and returns a single target resource
	returnCode=None
	capture=None
	#build request
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	request = urllib2.Request(url)
	if protocol == 'https': #build https request
		## create ssl context to ignore ssl cert error
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		##add header
		request.add_header('User-Agent', user_agent)
		## create opener(s)
		proxy_handler = urllib2.ProxyHandler({'https': proxy})
		## ssl context *must* be in the handler. if its added as an urlopen parameter
		## it will *not* use the proxy
		opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx), proxy_handler)
		##install opener
		urllib2.install_opener(opener)
		#make request using the installed opener
	else:
		##add header
		request.add_header('User-Agent', user_agent)
		## create opener(s)
		proxy_handler = urllib2.ProxyHandler({'http': proxy})
		## ssl context *must* be in the handler. if its added as an urlopen parameter
		## it will *not* use the proxy
		opener = urllib2.build_opener(proxy_handler)
		##install opener
		urllib2.install_opener(opener)
		#make request using the installed opener
	try:
		capture = urllib2.urlopen(request, timeout=12)
	except urllib2.URLError, e:
		if hasattr(e, 'reason'):
			print '\t\t---ERROR--- server could not be reached'
			#print '\t\tReason:',e.reason
		elif hasattr(e,code):
			print '\t\t---ERROR--- server could not handle request'
			#print '\t\tError code:',e.code
		else:
			print '\t\t---ERROR--- unknown error'
		pass
	except Exception, e:
		print '\t\t---ERROR--- unknown error',e
		pass
	else:
		returnCode=capture.getcode()
		#examine return code and bucket array
	return capture,returnCode;

def plunk( docBlob, fileName ): 
	#writes the target resource to a file on disk
	#write to file
	output=open(fileName,'w')
	try:
		output.write(docBlob.read())
	except Exception, e:
		print '\t\t---ERROR--- could not write file or file may be incomplete'
		pass
	else:
		output.close()
		print '\t... saved %s' %fileName
		print
	return;

def getDocs( proxyList, urlList ):
	#Retrieve documents for submitted list
	orphanedDocs=[] #initialize array
	capturedDocs=[] #initialize array
	print colored ('[*] retrieving documents/orphans', 'green')
	#if hotProxy != None:		
	for url in urlList:
		regex = r"(^http:.*)"
		matchObject = re.search(regex, url, flags=0)
		if matchObject:
			protocol='http'
		else:
			protocol='https'
		print '\t==> target is %s' %url
		print '\t... searching for %s proxy' %protocol
		hotProxy = find_proxy(protocol, proxyList)
		if hotProxy != None:	
			print '\t... retrieving %s' %url
			file_name = url.split('/')[-1]
			docBlob, returnIndicator = grab(url, hotProxy, protocol)
			if returnIndicator == 200 and docBlob is not None:
				capturedDocs.append( url )
				print '\t... captured %s' %url
				print '\t... saving %s' %file_name
				plunk(docBlob, file_name)
				#check = os.path.isfile(file_name)
				#if check:
				#	print '\t... saved %s' %file_name
				#else:
				#	print '\t---ERROR--- could not save %s' %file_name
				#print
			else:
				orphanedDocs.append( url )
				print '\t\t---CAUGHT--- adding %s to orphaned list' %file_name
				print
		else:
			print '\t\t---ERROR--- no available proxies cannot capture documents'
			print
	return capturedDocs, orphanedDocs

def results ( capturedList, orphanedList ):
	#displays results
	capturedCount = len(capturedList)
	orphanedCount = len(orphanedList)
	print '\t... captured %s documents' %capturedCount
	print '\t... orphaned %s documents' %orphanedCount
	print
	return;

def mopUp ( orphaned_Docs, captured_Docs, proxyList):
	#tries to retrieve missed documents one last time
	print '[*] executing mop-up' 
	print
	#hotProxy = find_proxy(proxyList)
	#if hotProxy is not None:
	captureddocsmopUp, orphaneddocsmopUp = getDocs(proxyList, orphaned_Docs)
	if captureddocsmopUp is not None:
		r=len(captureddocsmopUp)
		print '\t\t... %s additional documents captured' %r
		for i in captureddocsmopUp:
			captured_Docs.append(i)
	else:
		print '\t\t... no additional documents captured'
	#else:
	#	print '\t\t... could not find another proxy'
	#	print		
	return captured_Docs, orphaneddocsmopUp;

def main():
	url_file=''
	proxy_file=''
	#url_file = "urlList.txt"
	#proxy_file = "proxyList.txt"

	# [*] read in command line arguments
	myopts, args = getopt.getopt(sys.argv[1:], "u:p:h")

	for opt, arg in myopts:
		if opt == '-u':
			url_file=arg
		elif opt == '-p':
			proxy_file=arg
		elif opt == '-h':
			print
			print('\tUsage: %s -u <url file> -p <proxy file>' % sys.argv[0])
			print
			sys.exit()
		else:
			print
			print('\tUsage: %s -u <url file> -p <proxy file>' % sys.argv[0])
			print
			sys.exit()
	
	# [*] Read in file with URLs and return a python list
	print
	print colored('[*] reading in list of target URLs from %s' %url_file, 'green') 
	urlList = file_ingest(url_file)
	l = len(urlList)
	print '\t... there are %s targets to retrieve' %l
	print

	# [*] Read in file with proxies and return a python list
	print colored('[*] reading in list of proxies from %s' %proxy_file, 'green')
	proxyList = proxy_ingest(proxy_file)
	p = len(proxyList)
	print '\t... there are %s candidate proxies' %p
	print

	# [*] Retrieve documents
	# provides an array of URLs for captured docs and and array of URLs for missed/orphaned docs
	capturedDocs, orphanedDocs = getDocs(proxyList, urlList)

	# [*] Execute mop-up and print results
	if len(orphanedDocs) == 0:
		print colored ('[*] Results', 'green')
		if capturedDocs is not None and orphanedDocs is not None:
			results(capturedDocs, orphanedDocs)
			print colored ('[*] Have a nice day', 'green')
			print
	else:
		captureddocsFinal, orphaneddocsFinal = mopUp(orphanedDocs, capturedDocs, proxyList)
		print colored ('[*] Results', 'green')
		if captureddocsFinal is not None and orphaneddocsFinal is not None:
			results(captureddocsFinal, orphaneddocsFinal)
			print colored ('[*] Have a nice day', 'green')
			print

if __name__ == "__main__":
	main()