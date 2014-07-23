#!/usr/bin/perl

############################################################
##
##		proxy_diagnostics.pl v0.0.1
##		
##		Quickly test a list of open web proxies
##		
##		by pjhartlieb @ black lantern security group 
##
############################################################

#TBD
# Add small help file
# Verify list of proxies for correct format
# Add command line options for the proxy list file and output filename

#import modules
use HTML::Element;
use WWW::Mechanize;
use LWP::UserAgent;
use HTML::Parse;
use List::MoreUtils qw(uniq);
use strict;
use warnings;
use Data::Dumper;
use LWP::Simple;

#initialize variables
my @good_proxies;
my @bad_proxies;
my $frontpage = "http://www.walmart.com";

#open file - place contents in an array - count the number of proxies available
#file is assumed to be in the same directory that the script is run from
#filename is assumed to be "proxy_list.txt"
my $proxy_list = "proxy_list.txt";
open (F0, $proxy_list) || die "Could not open $proxy_list: $!\n";
my @f0 = <F0>;
close F0;
my @unique_proxies = uniq @f0;
print "\n";
print "[*] Reading in todays list of proxies.\n";
print "\n";
print "[*] There are " . scalar @unique_proxies . " unique proxies available today.\n";
print "\n";

#create and send a simple web request using a proxy
for my $proxy_ping (@f0) {
	print "[*] Testing " . $proxy_ping . "\n";
	my $mech = WWW::Mechanize->new (timeout=>30);
	$mech->proxy(['http'], "http://" . $proxy_ping);
	$mech->agent( 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)' );
	my $connection_1 = eval {						#make connection and catch any "GET" errors
    	$mech->get( $frontpage );
    	1
		};
	
	if (! $connection_1) {
    	push (@bad_proxies, $proxy_ping);
    	print "[*] ERROR. Unable to connect through proxy. \n";
    	print "\n";
    } else {
		push (@good_proxies, $proxy_ping);
		print "[*] Page Retrieved.  Proxy appears to be up. \n";
		print "\n";    	
    }	
}

#print good results
print "=============================================== \n\n";
print "[*] There are " . scalar @good_proxies . " proxies available today.\n\n";
print "[*] HOT PROXIES\n\n";
foreach my $proxy_kid (@good_proxies) {
    print "$proxy_kid \n";
}
print "\n";

#write results to file
my $outfile = 'hot_proxies.txt';

print "[*] Writing results to " . $outfile . "\n\n";

# here i 'open' the file, saying i want to write to it with the '>>' symbol
open (FILE, ">> $outfile") || die "[*] ERROR. Problem opening $outfile\n\n";

# write an array of lines to the file here
print FILE @good_proxies;

print "[*] Done. Have a nice day.\n\n";


