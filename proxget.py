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

#REFERENCE
# [1] http://www.blackhatlibrary.net/Security101_-_Blackhat_Techniques_-_Hacking_Tutorials_-_Vulnerability_Research_-_Security_Tools:General_disclaimer

#DISCLAIMER [1]

# This script is intended for educational purposes only.  
# I will not be held liable for a third party's use (or mis-use) of this information in any way.  
# Readers, end-users, and downloaders of content are responsible for their own actions.  
# Readers, end-users, and downloaders of content agree not to use content provided for illegal actions.  
# Content is provided as an educational resource for security researchers and penetration testers.

#tbd
## add arg parse so URL and proxy list files can be passed on the cmd line
## how will proxy be selected from hot list
## how will new proxy be selected if old proxy stops working
## modify grab function to accept list of URLS and proxy address

#url = "http://download.thinkbroadband.com/10MB.zip"
#file_name = url.split('/')[-1]

import urllib2
import socket
import errno

def file_ingest( url_list_file ): #parses file containing list of URLs and returns a list
	#write URLs to a python list
	with open(url_list_file, 'r') as infile:
		data = infile.read()
	urlList = data.splitlines()
	return urlList;

def proxy_ingest( proxy_list_file ): #parses file containing list of proxys and returns a list
	#write proxys to a python list
	with open(proxy_list_file, 'r') as infile:
		data = infile.read()
	proxyList = data.splitlines()
	return proxyList;

def proxy_test ( proxy_candidate): #tests a candidate proxy from list and returns a list of hot proxies
	#build request
	returnCode=None
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	test_url = "http://www.stackoverflow.com"
	request = urllib2.Request(test_url)
	##add header
	request.add_header('User-Agent', user_agent)
	## create opener(s)
	proxy_handler = urllib2.ProxyHandler({'http': proxy_candidate})
	opener = urllib2.build_opener(proxy_handler)
	##install opener
	urllib2.install_opener(opener)
	#make request
	try: 
		testResult = urllib2.urlopen(request, timeout=4)			
	except urllib2.URLError, e:
		if hasattr(e, 'reason'):
			print '\t\tServer could not be reached'
			print '\t\tReason:',e.reason
		elif hasattr(e,code):
			print '\t\tServer could not handle request'
			print '\t\tError code:',e.code
		else:
			print '\t\tUnknown error'
		pass
	except Exception, e:
		print '\t\tUnknown error',e
		pass
	else:
		returnCode=testResult.getcode()
	#examine return code and bucket array
	if returnCode == 200:
		return proxy_candidate;
	else:
		return;

def select_proxy ( hot_proxies ):
	# select candidate from array
	# remove candidate from array
	# send modified array back to caller
	candidate = hot_proxies.pop(0)
	proxyPool = hot_proxies
	return candidate,proxyPool;

def grab( url_list, proxy ): #retrieves and returns the target resource
	capturedDocs=[] #initialize array
	orphanedDocs=[] #initialize array
	returnCode=None
	for url in url_list:
		#build request
		user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
		request = urllib2.Request(url)
		##add header
		request.add_header('User-Agent', user_agent)
		## create opener(s)
		proxy_handler = urllib2.ProxyHandler({'http': proxy})
		opener = urllib2.build_opener(proxy_handler)
		##install opener
		urllib2.install_opener(opener)
		#make request using the installed opener
		try:
			capture = urllib2.urlopen(request, timeout=4)
		except urllib2.URLError, e:
			if hasattr(e, 'reason'):
				print '\t\tServer could not be reached'
				print '\tReason:',e.reason
			elif hasattr(e,code):
				print '\t\tServer could not handle request'
				print '\t\tError code:',e.code
			else:
				print '\t\tUnknown error'
			continue
		except Exception, e:
			print '\t\tUnknown error',e
			continue
		else:
			returnCode=capture.getcode()
			#examine return code and bucket array
			if returnCode == 200:
				capturedDocs.append( url )
				print 'Captured',url
				print
			else:
				orphanedDocs.append( url )
				print 'Orphaned',url
				print
	return capture;

def plunk( docBlob ): #writes the target resource to a file on disk
	#write to file
	output=open('test.pdf','wb')
	output.write(docBlob.read())
	output.close()
	return;

# [*] MAIN

# variable definitions
candidate_url = "http://www.paterva.com/MSL.pdf"
url_file = "urlList.txt"
proxy_file = "proxyList.txt"

# read in file with URLs and return a python list
print '[*] reading in list of target URLs'
urlList = file_ingest(url_file)
l = len(urlList)
print '\t... there are %s targets to retrieve' %l
print

# read in file with proxies and return a python list
print '[*] reading in list of proxies'
proxyList = proxy_ingest(proxy_file)
p = len(proxyList)
print '\t... there are %s candidate proxies' %p
print

# test proxies
hotProxy=[] #initialize array
print '[*] Testing proxies'
for proxy in proxyList:
	print '\tTesting %s' %proxy
	candidate = proxy_test(proxy)
	#print candidate
	if candidate:
		hotProxy.append(candidate)
		print '\t\t... %s is hot' %candidate
		print	
	else:
		print '\t\t...  no response'
		print

# select proxy
print '[*] Selecting proxies'
proxy, proxyPool = select_proxy(hotProxy)
print '\tSelected %s' %proxy
q = len(proxyPool)
print '\tThere are %s remaining proxies in reserve' %q

# retrieve documents
