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

# tbd
## add arg parse so URL and proxy list files can be passed on the cmd line
## must be able to select http *or* https proxy depending on what the url is
## more efficient would be if doc fails, retest proxy, it test fails, get new proxy and resume grab

import urllib2
import socket
import errno
import os
import ssl

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

def proxy_test ( proxy_candidate ): #tests a candidate proxy from list and returns a list of hot proxies
	#build request
	returnCode=None
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	test_url = "https://www.stackoverflow.com"
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	request = urllib2.Request(test_url)
	##add header
	request.add_header('User-Agent', user_agent)
	## create opener(s)
	proxy_handler = urllib2.ProxyHandler({'https': proxy_candidate})
	opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx), proxy_handler)
	##install opener
	urllib2.install_opener(opener)
	#make request
	try: 
		testResult = urllib2.urlopen(request, timeout=12)			
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

def select_proxy ( candidate_proxies ):
	# verify that there are candidates in the array
	# select candidate from raw array
	# remove candidate from array
	# send modified array (proxyPool) back to caller
	selectProxy = None
	if len(candidate_proxies) >= 1:
		selectProxy = candidate_proxies.pop(0)
		proxyPool = candidate_proxies
	else:
		print '\t... No more proxies to select from'
		#selectProxy = '0.0.0.0'
		proxyPool = None
		print
	return selectProxy,proxyPool;

def find_proxy ( raw_proxy_list ):
	# continue to submit and test proxies until a hot proxy is found
	# once found return the hot proxy and the remaining candidates to the caller
	print '[*] finding a hot proxy'
	hotProxy=None
	proxyPool=raw_proxy_list
	while hotProxy == None and len(proxyPool) != 0:
		selectProxy, proxyPool = select_proxy(raw_proxy_list)
		print '\t\t... trying %s' %selectProxy
		hotProxy = proxy_test(selectProxy)
		print
	else:
		if hotProxy != None:
			print '\t\t... %s is hot' %hotProxy
			print
		else:
			print'\t\t ... there are no remaining proxies to select from'
			print
	return hotProxy, proxyPool

def grab( url, proxy ): #retrieves and returns a target resource
	returnCode=None
	capture=None
	#build request
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	request = urllib2.Request(url)
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
	try:
		capture = urllib2.urlopen(request, timeout=12)
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
		returnCode=capture.getcode()
		#examine return code and bucket array
	return capture,returnCode;

def plunk( docBlob, fileName ): #writes the target resource to a file on disk
	#write to file
	output=open(fileName,'wb')
	output.write(docBlob.read())
	output.close()
	return;

def getDocs( hotProxy, urlList ):
	# [*] Retrieve documents
	orphanedDocs=[] #initialize array
	capturedDocs=[] #initialize array
	print '[*] retrieving documents'
	if hotProxy != None:		
		for url in urlList:
			print '\t... retrieving %s' %url
			file_name = url.split('/')[-1]
			docBlob, returnIndicator = grab(url, hotProxy)
			if returnIndicator == 200 and docBlob is not None:
				capturedDocs.append( url )
				print '\t... captured %s' %url
				print '\t... saving %s' %file_name
				plunk(docBlob, file_name)
				check = os.path.isfile(file_name)
				if check:
					print '\t... saved %s' %file_name
				else:
					print '\t... error saving %s' %file_name
				print
			else:
				orphanedDocs.append( url )
				print '\t... *error* adding %s to orphaned list' %file_name
				print
	else:
		print '\t\t ... no available proxies cannot capture documents'
		print
	return capturedDocs, orphanedDocs

def results ( capturedList, orphanedList ): # displays results
	capturedCount = len(capturedList)
	orphanedCount = len(orphanedList)
	print '\t... captured %s documents' %capturedCount
	print '\t... orphaned %s documents' %orphanedCount
	print
	return;

def mopUp ( orphaned_Docs, captured_Docs, proxypool_Current ):
	print '[*] executing mop-up' 
	print
	# check to make sure there are proxies left to work with
	if len(proxypool_Current) >= 1:
		hotProxy, proxypoolmopUp = find_proxy(proxypool_Current)
		if hotProxy is not None:
			captureddocsmopUp, orphaneddocsmopUp = getDocs(hotProxy, orphaned_Docs)
			if captureddocsmopUp is not None:
				r=len(captureddocsmopUp)
				print '\t\t... %s additional documents captured' %r
				for i in captureddocsmopUp:
					captured_Docs.append(i)
			else:
				print '\t\t... no additional documents captured'
		else:
			print '\t\t... could not find another proxy'
			print		
	else:
		print'\t\t... there are no candidate proxies left'
		print
	return captured_Docs, orphaneddocsmopUp;

#def Main ():
url_file = "urlList.txt"
proxy_file = "proxyList.txt"

# [*] Read in file with URLs and return a python list
print '[*] reading in list of target URLs'
urlList = file_ingest(url_file)
l = len(urlList)
print '\t... there are %s targets to retrieve' %l
print

# [*] Read in file with proxies and return a python list
print '[*] reading in list of proxies'
proxyList = proxy_ingest(proxy_file)
p = len(proxyList)
print '\t... there are %s candidate proxies' %p
print

# [*] Find proxy
# provides a hot proxy and the remaining pool of candidate proxy servers
hotproxyCurrent, proxypoolCurrent = find_proxy(proxyList)
#print hotproxyCurrent
#print

# [*] Retrieve documents
# provides an array of URLs for captured docs and and array of URLs for missed/orphaned docs
capturedDocs, orphanedDocs = getDocs(hotproxyCurrent, urlList)

# [*] Execute mop-up
# one more attempt to capture documents that were missed
if len(orphanedDocs) == 0:
	print '[*] Results'
	if capturedDocs is not None and orphanedDocs is not None:
		results(capturedDocs, orphanedDocs)
		print '[*] Have a nice day'
else:
	captureddocsFinal, orphaneddocsFinal = mopUp(orphanedDocs, capturedDocs, proxypoolCurrent)
	print '[*] Results'
	if captureddocsFinal is not None and orphaneddocsFinal is not None:
		results(captureddocsFinal, orphaneddocsFinal)
		print '[*] Have a nice day'