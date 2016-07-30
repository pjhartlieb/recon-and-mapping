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

def grab( url ): #retrieves and returns the target resource
	capturedDocs=[] #initialize array
	#build request
	user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
	request = urllib2.Request(url)
	##add header
	request.add_header('User-Agent', user_agent)
	## create opener(s)
	proxy_handler = urllib2.ProxyHandler({'http': 'http://:80'})
	opener = urllib2.build_opener(proxy_handler)
	##install opener
	urllib2.install_opener(opener)
	#make request using the installed opener
	try:
		capture = urllib2.urlopen(request, timeout=4)
	except urllib2.URLError, e:
		if hasattr(e, 'reason'):
			print 'Server could not be reached'
			print 'Reason:',e.reason
			print
		elif hasattr(e,code):
			print 'Server could not handle request'
			print 'Error code:',e.code
			print
		else:
			print 'Unknown error'
			print
		pass
	except Exception, e:
		print e
		print
		pass
	else:
		returnCode=capture.getcode()
		#examine return code and bucket array
		if returnCode == 200:
			capturedDocs.append( url )
			print 'Captured',url
			print
		else:
			print
	return capture;

def plunk( docBlob ): #writes the target resource to a file on disk
	#write to file
	output=open('test.pdf','wb')
	output.write(docBlob.read())
	output.close()
	return;

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

def proxy_test ( proxy_list ): #tests each candidate proxy from list and returns a list of hot proxies
	hotProxy=[] #initialize array
	for proxy in proxy_list:
		print 'Testing:', proxy
		#build request
		user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
		test_url = "http://www.stackoverflow.com"
		request = urllib2.Request(test_url)
		##add header
		request.add_header('User-Agent', user_agent)
		## create opener(s)
		proxy_handler = urllib2.ProxyHandler({'http': proxy})
		opener = urllib2.build_opener(proxy_handler)
		##install opener
		urllib2.install_opener(opener)
		#make request
		try: 
			testResult = urllib2.urlopen(request, timeout=4)			
		except urllib2.URLError, e:
			if hasattr(e, 'reason'):
				print 'Server could not be reached'
				print 'Reason:',e.reason
				print
			elif hasattr(e,code):
				print 'Server could not handle request'
				print 'Error code:',e.code
				print
			else:
				print 'Unknown error'
				print
			continue
		except Exception, e:
			print e
			print
			continue
		else:
			returnCode=testResult.getcode()
			#examine return code and bucket array
			if returnCode == 200:
				hotProxy.append( proxy )
				print 'Proxy is up'
				print
			else:
				print
	return hotProxy;

#docBlob = grab(candidate_url)
#plunk(docBlob)
#bleeb = proxy_ingest(proxy_file)
#bloob = proxy_test(bleeb)
#print 'The list of hot proxies includes:'
#print
#for line in bloob:
#	print line

#main flow

## variable definitions

candidate_url = "http://www.paterva.com/MSL.pdf"
url_file = "urlList.txt"
proxy_file = "proxyList.txt"

## read in file with URLs and return a python list

urlList = file_ingest(url_file)
l = len(urlList)
print l

## read in file with proxies and return a python list

proxyList = proxy_ingest(proxy_file)
p = len(proxyList)
print p

## test proxies and return a list of hot proxies

hotproxyList = proxy_test(proxyList)
hp = len(hotproxyList)
print hp

## for each URL call the grab function and pass one URL and one hot proxy

## the grab function needs to return the binary blob and a file name

## for each capture returned call the plunk function with the binary blob and filename and write it to disk
