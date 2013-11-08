#!/usr/bin/perl

#########################################
# osint_yatedo_scraper v0.0.3 - Dev 09/12/2013
# By pjhartlieb
# http://pjhartlieb.blogspot.com
#########################################

# This script will scrape yatedo search results for a specific company
## tbd
## handle timeouts
## finish help file
## help and command line options
## clean up
## correct link account for additional results pages
## hard code www.yatedo.com DONE
## write results to file
## improve look of output
## functionalize everything
## work case where the title contains useful data

#import modules
use HTML::Element;
use Carp;
use WWW::Mechanize;
use HTML::TreeBuilder;
use LWP::UserAgent;
use HTML::Parse;
use List::MoreUtils qw(uniq);
use strict;
use warnings;
use Data::Dumper;
use HTML::Tree;
use LWP::Simple;
use Getopt::Long;

# command line options
my $help;
#my $delay = 0;
#my $dns;

# processing command line options
my $result = GetOptions (	
			'help'		=> \$help,
			); 
			
help()                   if $help;

#global variables
	my $range = 10; #range for random sleep times

#define end user arguments
	my $target_site = "www.yatedo.com";
	my $keyword = $ARGV[0];

#request frontpage
## initialize variables
	my $mech = WWW::Mechanize->new();
	my $frontpage = "http://${target_site}";
	my @forms;
	my $content;
	my $cookie_jar;
	
## set user-agent
	$mech->agent( 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)' );
	
## retrieve frontpage
	print "\n";
	print "[*] Retrieving frontpage for " . $target_site . " \n";
	$mech->get( $frontpage );

## sleep
	my $random_number = int(rand($range));		#generate random integer between 0-20 s
	print "[*] Sleeping for " . $random_number . " seconds to avoid lockout \n";
	print "\n";
	sleep($random_number);

## retrieve cookies and dump forms from frontpage
	#$cookie_jar = $mech->cookie_jar();      #This is an instance of the HTML::Cookies object.  Assigns variable to the content of cookie jar for error checking
	#$mech->dump_forms( @forms );            #dump all forms from page to @forms
	#print @forms;                           #print form data

#submit yatedo search with captured cookies
## set form parameters
	print "[*] Submitting search for " . $keyword . "\n";
	$mech->submit_form(						#cookies will be automatically included with the request
        	form_number => 1,
        	fields => {
                	q => "companyname:(($keyword))",
                	c => 'all',
                	start => 0,
					p => 1,
					advs => 0,
					rlg => 'en',
                	},
        	button => 'btn_es');

##verify and decode content
	if ($mech->success) {
        	$content = $mech->response()->decoded_content();
        	print "[*] Search successful. Content retrieved \n";
		#print "Cookie:\n" . $cookie_jar->as_string; #returns cookies as a series of "Set-Cookie3" header lines separated by "\n"
        } else {
        	die ("[*] ERROR. No content returned. Exiting \n");
        }
        
##extract all links for people *and* results pages on the returned page
	my @links = $mech->find_all_links( url_regex => qr/\/p\/.*|\/s\/.*/);		#/p is an individual /s is a page with additional results
	my @url;
	for my $link (@links) {														#create absolute URLs 										
		push (@url, $link->url_abs);
		}
	my @uniq_url = uniq(@url);													#remove duplicate URLs
	print "[*] " . scalar @uniq_url . " unique links to human targets and additional results pages were found on the first page \n";
	
##extract the link to *all* results and sleep
	my $all_in;
	for my $all (@uniq_url) {
		if ($all =~ m/.*\/normal$/) {
			print "[*] Cummulative results are here: " . $all . "\n";
			$all_in = $all;
			}
		}
	my $random_number_2 = int(rand($range));
	print "[*] Sleeping for " . $random_number_2 . " seconds to avoid lockout\n";
	print "\n";
	sleep($random_number_2);
	
##retrive __first__ page with cumulative results
	print "[*] Retrieving cumulative results for " . $keyword . " \n";		#retrieve and verify content
	$mech->get( $all_in );													
	if ($mech->success) {
        	my $content_2 = $mech->response()->decoded_content();
        	print "[*] Successful. Content retrieved \n";
        } else {
        	die ("[*] ERROR. No content returned. Exiting \n");
        }

##parse out links to people *and* links to additional results pages
    
    my @target_links = $mech->find_all_links( url_regex => qr/\/p\/[a-zA-Z\+].*\/normal\/.*/);	#target individuals
    my @page_links = $mech->find_all_links( url_regex => qr/&p=.*$/);		#results pages
	
	my @target_url; 														#create absolute urls
	for my $target_link (@target_links) {
		push (@target_url, $target_link->url_abs);
		}
		
	my @page_url; 															#create absolute urls
	for my $page_link (@page_links) {
		push (@page_url, $page_link->url_abs);
		}
	
	my @uniq_target_url = uniq(@target_url);								#remove duplicates from target array
	print "[*] " . scalar @uniq_target_url . " Links to human targets found \n";
	
	my @uniq_page_url = uniq(@page_url);									#remove duplicates from additional pages of results
	print "[*] " . scalar @uniq_page_url . " Links to additional results pages found \n";
	print "\n";
	
##retrieve and scrape data for the first page of results

	my  @humint_targets;						#initialize array to store results
	my	$humint_targets;						#initialize variable to count results
	print "[*] Harvesting human target data with sleep times between 0 and " . $range . " seconds between records \n";
	print "\n";
	for my $uniq_target_url (@uniq_target_url) {
		#print "[*] Scraping data from " . $uniq_target_url . " \n";
		$mech->get( $uniq_target_url );
		my $scraping = $mech-> content;		#response()->decoded_content();
		#print $scraping . "\n";
		
		#create trees to walk the content of the target pages 
		my $tree_iter = HTML::Tree->new(); #create new tree object
	
		$tree_iter->parse($scraping);		#populate tree object with parsed content
		
		my $span_first;
		my ($span_f) = $tree_iter->look_down(	#extract firstname and print as text
			_tag => "span",
			class => "given-name firstname",
			);
			if(length($span_f) != 0) {
				$span_first = $span_f->as_text;
			} else {
				$span_first = "undef";
			}
		
		my $span_last;
		my ($span_l) = $tree_iter->look_down(	#extract lastname and print as text
			_tag => "span",
			class => "family-name lastname",
			);
			if(length($span_f) != 0) {
				$span_last = $span_l->as_text;
			} else {
				$span_last = "undef";
			}

		my $span_org;
		my ($span_o) = $tree_iter->look_down(	#extract organization and print as text
			_tag => "span",
			class => "org",
			);
			#if(length($span_o) != 0) {
			if(defined ($span_o)) {
				$span_org = $span_o->as_text;
			} else {
				$span_org = "undef|past-employer";
			}
		
		my $span_role;
		my ($span_r) = $tree_iter->look_down(	#extract role and print as text
			_tag => "span",
			class => "role",
			);
			#if(length($span_r) != 0) {
			if(defined ($span_r)) {
				$span_role = $span_r->as_text;
			} else {
				$span_role = "undef|past-role";
			}
		if ($span_org =~ m/.*($keyword).*/i) {
			my $entry="$span_first,$span_last,$span_org,$span_role";
			push (@humint_targets, $entry);
		}
		
		my $random_number_2 = int(rand($range));
		sleep($random_number_2);
	}

$humint_targets = scalar @humint_targets;
print "[*] " . $humint_targets . " suitable human targets found to date \n";
print "\n";

## retrieve the __all other__ pages of results

for my $uniq_page_url (@uniq_page_url) {
	my $add=1;
	my $current_count= scalar @uniq_page_url;
	$current_count+=$add;
	$uniq_page_url =~ m/(\d+)$/;	#extract the page identifier
	my $results_page=$1;			#assign the identifier to $results_page		
	
	print "[*] Retrieving target URLs from results page " . $results_page . " \n";		#retrieve and verify content
	$mech->get( $uniq_page_url );													
	if ($mech->success) {
        	my $content = $mech->response()->decoded_content();
        	print "[*] Successful. Content retrieved \n";
        } else {
        	die ("[*] ERROR. No content returned. Exiting \n");
        }
## parse out links to people *and* links to additional results pages
    
    my @target_links_i = $mech->find_all_links( url_regex => qr/\/p\/[a-zA-Z\+].*\/normal\/.*/);	#target individuals
    my @page_links_i = $mech->find_all_links( url_regex => qr/&p=.*$/);								#results pages
    
    my @target_url_i; 																				#create absolute urls
	for my $target_link_i (@target_links_i) {
		push (@target_url_i, $target_link_i->url_abs);
		}
		
	my @page_url_i; 																				#create absolute urls
	for my $page_link_i (@page_links_i) {
		push (@page_url_i, $page_link_i->url_abs);
		}
	
	my @uniq_target_url_i = uniq(@target_url_i);													#remove duplicates from target array
	print "[*] " . scalar @uniq_target_url_i . " Links to human targets found \n";
	
	my @uniq_page_url_i = uniq(@page_url_i);														#remove duplicates from additional pages of results
	my $new_page_count=0;
	for my $page_url_i (@uniq_page_url_i) {
		$page_url_i =~ m/(\d+)$/;
		my $harvested_identifier=$1;
		if ($harvested_identifier > $current_count) {
			push (@uniq_page_url, $page_url_i);
			++$new_page_count;
			}
		}
	print "[*] " . $new_page_count . " Links to additonal results pages found \n";
	print "\n";
	
	##parse out the targets on the current page
	print "[*] Harvesting human target data with sleep times between 0 and " . $range . " seconds between records \n";
	print "\n";
		for my $uniq_target_url_i (@uniq_target_url_i) {
			#print "[*] Scraping data from " . $uniq_target_url_i . " \n";
			$mech->get( $uniq_target_url_i );
			my $scraping_i = $mech->content;		#response()->decoded_content();
			#print $scraping . "\n";
		
			#create trees to walk the content of the target pages 
			my $tree_iter_i = HTML::Tree->new(); #create new tree object
	
			$tree_iter_i->parse($scraping_i);		#populate tree object with parsed content
		
			my $span_first_i;
			my ($span_f_i) = $tree_iter_i->look_down(	#extract firstname and print as text
				_tag => "span",
				class => "given-name firstname",
				);
			if(length($span_f_i) != 0) {
				$span_first_i = $span_f_i->as_text;
			} else {
				$span_first_i = "undef";
			}
		
			my $span_last_i;
			my ($span_l_i) = $tree_iter_i->look_down(	#extract lastname and print as text
				_tag => "span",
				class => "family-name lastname",
				);
			if(length($span_l_i) != 0) {
				$span_last_i = $span_l_i->as_text;
			} else {
				$span_last_i = "undef";
			}

			my $span_org_i;
			my ($span_o_i) = $tree_iter_i->look_down(	#extract organization and print as text
				_tag => "span",
				class => "org",
				);
			#if(length($span_o_i) != 0) {
			if(defined ($span_o_i)) {
				$span_org_i = $span_o_i->as_text;
			} else {
				$span_org_i = "undef|past-employer";
			}
		
			my $span_role_i;
			my ($span_r_i) = $tree_iter_i->look_down(	#extract role and print as text
				_tag => "span",
				class => "role",
				);
			if(defined ($span_r_i)) {	
			#if(length($span_r_i) != 0) {
				$span_role_i = $span_r_i->as_text;
			} else {
				$span_role_i = "undef|past-role";
			}
		if ($span_org_i =~ m/.*($keyword).*/i) {
			my $entry="$span_first_i,$span_last_i,$span_org_i,$span_role_i";
			push (@humint_targets, $entry);
		}
		
		my $random_number_2 = int(rand($range));
		sleep($random_number_2);
	}
	$humint_targets = scalar @humint_targets;
	print "[*] " . $humint_targets . " suitable human targets found to date \n";
	print "\n";
}
print "[*] candidate target list \n";
print "\n";
print join("\n", @humint_targets), "\n";
print "\n";

sub help {
  print <<EOHELP;
  
osint_yatedo_scraper.pl By pjhartlieb at http://blogspot.pjhartlieb.com

		Usage: perl osint_yatedo_sctaper.pl [OPTIONS] www.yatedo.com <keyword>

Overview:
		Query Yatedo for human targets in a specific organization and display the
		results in csv format. 

Options:
	
		-help		This screen.
		-keyword	This is the keyword that will be submitted with the Yatedo query
		-sleep		This is the range in seconds that will be used to generate a random
					delay to avoid lockout. 

Example:

		perl osint_yatedo_scraper.pl www.yatedo.com walmart
	 
EOHELP
exit;
}

