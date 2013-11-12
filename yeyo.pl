#!/usr/bin/perl

############################################################
##
##		yeyo.pl v0.0.4
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

# This script will scrape yatedo search results for a specific company
## TBD
## **need** to catch errors using eval.  right now it will shit the bed if mech cannot connect DONE! (I think)
## correct link account for additional results pages
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

#global variables
my $target_site = "www.yatedo.com";

# command line options
my $help;
my $keyword;  #keyword or target organization
my $range=10; #range for random sleep times

# processing command line options
my $result = GetOptions (	
			'help'		=> \$help,
			'keyword=s'	=> \$keyword,
			'sleep:i'	=> \$range,
			); 
			
help()                   if $help;

#check to make sure the keyword is provided
	print "\n[*] Validating keyword/organization ...\n";
	if ( defined $keyword ) {
		# do nothing
		} else {
		die("\n[*] ERROR. please provide a reasonable keyword or organization. Use -h for help \n\n");
	}

#operate on keyword to improve search results

	

#check to make sure the sleep time is valid
	print "[*] Validating sleep time ...\n";
	if ( $range >= 0 ) {
		# do nothing
		} else {
		die("\n[*] ERROR. please provide a reasonable sleep time. Use -h for help \n\n");
	}

#read out the keyword
	print "[*] Keyword entered \"$keyword\". \n";

#read out the sleep time
	print "[*] Sleep times will be between 0 and $range. \n";

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
	#$mech->get( $frontpage );
	
	my $connection_1 = eval {						#make connection and catch any "GET" errors
    	$mech->get( $frontpage );
    	1
		};
	
	if (! $connection_1) {
    	print "[*] ERROR. Unable to retrieve frontpage. \n";
	};

	if ($mech->success) {
		print "[*] Yatedo appears to be up \n";
	    } else {
	        die ("[*] ERROR. Yatedo does not appear to be responding. Exiting \n\n");
	}

## sleep
	my $random_number = int(rand($range));		#generate random integer between 0-20 s
	print "[*] Sleeping for " . $random_number . " seconds to avoid lockout \n";
	print "\n";
	sleep($random_number);

#submit yatedo search with captured cookies
## set form parameters
	print "[*] Submitting search for " . $keyword . "\n";
	my $connection_2 = eval {
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
		1
		};

		if (! $connection_1) {
    	print "[*] ERROR. Unable to submit search. \n";
		};

##verify and decode content
	if ($mech->success) {
		print "[*] Search successful. Content retrieved \n";
        $content = $mech->response()->decoded_content();	
        } else {
        	die ("[*] ERROR. No content returned. You may want to try a different keyword. Exiting \n\n");
    }
        
##extract all links for people *and* results pages on the returned page
	my @links = $mech->find_all_links( url_regex => qr/\/p\/.*|\/s\/.*/);		#/p is an individual /s is a page with additional results
	my @url;
	for my $link (@links) {														#create absolute URLs 										
		push (@url, $link->url_abs);
	}
	my @uniq_url = uniq(@url);													#remove duplicate URLs
	print "[*] " . scalar @uniq_url . " unique links to users and additional results pages were found on the first page \n";
	
##extract the link to *all* pulbic profiles tied to the keyword results and sleep
	my $all_in;
	for my $all (@uniq_url) {
		if ($all =~ m/.*\/normal$/) {											#if "normal" is in the URL, this is a special address
			print "[*] Cummulative results are here: " . $all . "\n";
			$all_in = $all;
		}
	}
	my $random_number_2 = int(rand($range));
	print "[*] Sleeping for " . $random_number_2 . " seconds to avoid lockout\n";
	print "\n";
	sleep($random_number_2);
	
##retrive page with links and results for all public profiles
	print "[*] Retrieving cumulative results for " . $keyword . " \n";			#retrieve and verify content
	my $connection_3 = eval {
		$mech->get( $all_in );
		1
		};

		if (! $connection_1) {
    	print "[*] ERROR. Unable to retrieve list of public profiles. \n";
		};	

	if ($mech->success) {
        	my $content_2 = $mech->response()->decoded_content();
        	print "[*] Successful. Content retrieved \n";
        } else {
        	die ("[*] ERROR. No content returned from " . $all_in . " . Exiting \n\n");
    }

##parse out links to people *and* links to additional results pages  
    my @target_links = $mech->find_all_links( url_regex => qr/\/p\/[a-zA-Z\+].*\/normal\/.*/);	#target individuals
    my @page_links = $mech->find_all_links( url_regex => qr/&p=.*$/);							#results pages
	
	my @target_url; 																			#create absolute urls
	for my $target_link (@target_links) {
		push (@target_url, $target_link->url_abs);
	}
		
	my @page_url; 																				#create absolute urls
	for my $page_link (@page_links) {
		push (@page_url, $page_link->url_abs);
	}
	
	my @uniq_target_url = uniq(@target_url);													#remove duplicates from target array
	print "[*] " . scalar @uniq_target_url . " Links to users found \n";
	
	my @uniq_page_url = uniq(@page_url);														#remove duplicates from additional pages of results
	print "[*] " . scalar @uniq_page_url . " Links to additional results pages found \n";
	print "\n";
	
##retrieve and scrape data for the first page of results

	my  @humint_users;						#initialize array to store results
	my	$humint_users;						#initialize variable to count results

	print "[*] Harvesting user data with sleep times between 0 and " . $range . " seconds between records \n";
	print "\n";
	for my $uniq_target_url (@uniq_target_url) {
		my $connection_4 = eval {
			$mech->get( $uniq_target_url );
			1
			};

		if (! $connection_4 ) {
    	print "[*] ERROR. Unable to retrieve target data for $uniq_target_url. Moving on. \n";
		} else {	

			if ($mech->success) {
	      
				my $scraping = $mech-> content;		#response()->decoded_content();
				
				#create trees to walk the content of the target pages 
				my $tree_iter = HTML::Tree->new(); 		#create new tree object
			
				$tree_iter->parse($scraping);			#populate tree object with parsed content
				
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
					if(defined ($span_r)) {
						$span_role = $span_r->as_text;
					} else {
						$span_role = "undef|past-role";
					}
				if ($span_org =~ m/.*($keyword).*/i) {
					my $entry="$span_first,$span_last,$span_org,$span_role";
					push (@humint_users, $entry);
				}
				
				my $random_number_2 = int(rand($range));
				sleep($random_number_2);

				} else {
        		print ("[*] ERROR. Could not retrieve target data for " . $uniq_target_url . " . Moving on. \n");
        	}	#close if/then for mech success
        }	#close if/then for eva statement error catching
	}	#close for loop 

	$humint_users = scalar @humint_users;
	print "[*] " . $humint_users . " suitable users found to date \n";
	print "\n";

## retrieve target data from all other pages of results
for my $uniq_page_url (@uniq_page_url) {			
	my $add=1;									#the next bit of code makes for an accurate accounting of results pages
	my $current_count= scalar @uniq_page_url;	#count the total # of results pages found so far	
	$current_count+=$add;						#increment it by one as a correction
	$uniq_page_url =~ m/(\d+)$/;				#extract the page identifier from the current page we are scraping
	my $results_page=$1;						#assign the identifier to $results_page	variable.
	
	print "[*] Retrieving target URLs from results page " . $results_page . " \n";		#retrieve and verify content
	my $connection_5 = eval {
		$mech->get( $uniq_page_url );
		1
		};
	
	if (! $connection_5 ) {
    	print "[*] ERROR. Unable to retrieve results from page $results_page. Moving on. \n";
		} else {
			if ($mech->success) {
		        my $content = $mech->response()->decoded_content();
		        print "[*] Successful. Content retrieved \n";

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
				print "[*] " . scalar @uniq_target_url_i . " Links to users found \n";
			
				my @uniq_page_url_i = uniq(@page_url_i);														#remove duplicates from additional pages of results
				my $new_page_count=0;																			#this is a counter to check for new results pages
				for my $page_url_i (@uniq_page_url_i) {															#for each result page extract the identifier
					$page_url_i =~ m/(\d+)$/;
					my $harvested_identifier=$1;																#assign the identifier to a variable
					if ($harvested_identifier > $current_count) {												#look to see if this is a "new" results page
						push (@uniq_page_url, $page_url_i);														#if so push it to the array of results pages
						++$new_page_count;																		#increment the counter	
					}
				}
				print "[*] " . $new_page_count . " Links to additonal results pages found \n";					#print the total number of new pages found
				print "\n";
			
				##parse out the users on the current page
				print "[*] Harvesting user data with sleep times between 0 and " . $range . " seconds between records \n";
				print "\n";
					for my $uniq_target_url_i (@uniq_target_url_i) {
						my $connection_6 = eval {
							$mech->get( $uniq_target_url_i );
							1
						};

						if (! $connection_6 ) {
    						print "[*] ERROR. Unable to retrieve target data for $uniq_target_url_i. Moving on. \n";
						} else {

							if ($mech->success) {

								my $scraping_i = $mech->content;		#response()->decoded_content();
							
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
									push (@humint_users, $entry);
								}
						
								my $random_number_2 = int(rand($range));
								sleep($random_number_2);
							
							} else {
			        			print ("[*] ERROR. Could not retrieve " . $uniq_target_url_i . " Moving on. \n");
			    			}	#close if/then for mech success
			    		}	#close if/then for eval statement catching errors (connection 6)
					}	#close for loop for iterating through individual users
			
				$humint_users = scalar @humint_users;
				print "[*] " . $humint_users . " suitable users found to date \n";
				print "\n";

				} else {
        			print ("[*] ERROR. Could not retrieve results page " . $uniq_page_url . " Moving on. \n");
    		}	#close if/then for mech success statement
    }	#close if/then for eval statement catching errors (connection 5)
}	#close ouer for loop for results pages

print "[*] candidate user list \n";
print "\n";
print join("\n", @humint_users), "\n";
print "\n";

sub help {
  print <<EOHELP;
  
osint_yatedo_scraper.pl By pjhartlieb at http://blogspot.pjhartlieb.com

		Usage: perl osint_yatedo_sctaper.pl [OPTIONS] www.yatedo.com <keyword>

Overview:
		Query Yatedo for users in a specific organization and display the
		results in csv format. 

Options:
	
		-help		This screen.
		-keyword	This is the keyword/organization that will be submitted with the Yatedo query
		-sleep		This is the range in seconds that will be used to generate a random delay to 
				avoid lockout. The default value is 10.

Example:

		perl osint_yatedo_scraper.pl -keyword walmart -sleep 5
		perl osint_yatedo_scraper.pl -keyword "five guys" -sleep 5
	 
EOHELP
exit;
}

