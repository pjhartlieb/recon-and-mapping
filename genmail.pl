#!/usr/bin/perl

############################################################
##
##		genmail.pl v0.0.4
##		
##		Generates email addresses for a specific domain
##		given a list of non-uniform usernames.
##		
##		by pjhartlieb @ black lantern security group 
##
############################################################

#DISCLAIMER [1]

# This script is intended for educational purposes only.  
# I will not be held liable for a third party's use (or mis-use) of this information in any way.  
# Readers, end-users, and downloaders of content are responsible for their own actions.  
# Readers, end-users, and downloaders of content agree not to use content provided for illegal actions.  
# Content is provided as an educational resource for security researchers and penetration testers.

#REFERENCE
#http://www.blackhatlibrary.net/Security101_-_Blackhat_Techniques_-_Hacking_Tutorials_-_Vulnerability_Research_-_Security_Tools:General_disclaimer

#TBD
## clean and tighten
## read in mulitple domains as a flat file
## create commandline option to let enduser choose the final email formats
## need to deal with last,first and first,Mi,last
## provide options for reading in a single name on the command line instead of a file
## include a list of default usernames.  These should kick out even if no user list is provided

#modules
use strict;
use Getopt::Long;

# command line options
my $help;
my $filename;
my $domain;

# processing command line options
my $result = GetOptions (	
			'help'		=> \$help,
			'domain=s'	=> \$domain,
			'filename=s'	=> \$filename,
			); 
			
help()                   if $help;

#read in the target file
print "\n";
print "[*]	File name entered \"$filename\" \n\n";

#read in the target domain
print "[*]	Target domain \"$domain\" \n\n";

#check to make sure the file provided exists
if (-e $filename) {
	print "[*]	File exists.\n\n";
	print "[*]	Executing.\n\n";
	} else {
	die("[*]	ERROR. please provide a valid file. Use -h for help \n\n");
	}

#check to make sure the domain is formatted correctly
if ( $domain =~ m/^([a-zA-Z0-9\-]{1,}\.){1,}[a-zA-Z0-9\-]{1,}$/ ) {
	print "[*]	Domain appears to be formatted correctly. Proceeding\n\n";
} else {
	die("[*]	ERROR. Please provide a valid domain. Use -h for help \n\n");	
}

#read each line of the target file into an array
open (TARGET_FILE, $filename) or die "[*] can't read file: $!\n\n";	#create filehandle

##populate the array using the file handle
my @base_array=<TARGET_FILE>;

##initialize the email address arrays
my @domain=();

#parse through usernames and *whenever* possible generate multiple username formats for the email prefix
##initialize the username arrays for multiple formats that may appear in the target file
my @first_dot_last=();				#Capture names in the first.last ("john.doe") format
my @first_dot_mi_dot_last=();		#Capture names in the first.mi.last ("john.q.doe") format
my @Last_FI_MI=();					#Capture names in the LastFiMi ("DoeJQ") format
my @FI_MI_Last=();					#Capture names in the FiMiLast ("JQDoe") format
my @irregular=();					#Capture irregular usernames that could not be parsed into a useable form
my @alpha=("a".."z");				#Alphabetic array for generating middle intials

foreach (@base_array) {
	if ( $_ =~ m/^([a-z]{1,})[\s]{1,}([a-z]{1,})$/i ) {	#capture usernames in the case insensitive "first<sp>last" format		
		foreach my $alpha (@alpha) {				#generate usernames with a middle initial
			my $capture_qq="$1\.$alpha\.$2";		#rewrite new format which includes all possible middle initials
													# $1 and $2 are captured using () in the regex
			push (@first_dot_mi_dot_last, $capture_qq);		#write to "first.mi.last" array
			}
		my $capture_vv="$1\.$2";					#capture name with no middle initial
		push (@first_dot_last, $capture_vv);		#write "first.last" to array
																		
	} elsif ( $_ =~ m/^([a-z]{1,})([\s]{1,})([a-z]{1,})([\s]{1,})([a-z]{1,})$/i ) { 	#capture usernames in the case insensitive "first<sp>middle<sp>last" format		
		my $capture_qq=substr($3, 0, 1);			#capture the middle initial
		my $capture_vv="$1\.$capture_qq\.$5";		#rewrite new format
		push (@first_dot_mi_dot_last, $capture_vv);	#write to "first.mi.last" array		
		my $capture_ww="$1\.$5";				 	#write to "first.last" format
		push (@first_dot_last, $capture_ww);		#write to "first.last" array

	} elsif ( $_ =~ m/^([a-z]{1,})\s([a-z]{1,1})\s([a-z]{1,})$/i ) { 	#capture usernames in the case insensitive "first<sp>mi<sp>last" format		
		my $capture_qq="$1\.$2\.$3";				#rewrite new format which includes all possible middle initials
		push (@first_dot_mi_dot_last, $capture_qq);	#write to "first.mi.last" array
		
		my $capture_vv="$1\.$3";					#capture name with no middle initial
		push (@first_dot_last, $capture_vv);		#write "first.last" to array

	} elsif ( $_ =~ m/^([a-z]{1,})\s([a-z]{1,1})\.\s([a-z]{1,})$/i ) {	#capture usernames in the case insensitive "first<sp>mi.<sp>last" format		
		my $capture_qq="$1\.$2\.$3";				#rewrite new format
		push (@first_dot_mi_dot_last, $capture_qq);	#write to "first.mi.last" array
		
		my $capture_vv="$1\.$3";					#capture name with no middle initial
		push (@first_dot_last, $capture_vv);		#write "first.last" to array

	} elsif ( $_=~ m/^([A-Z]{1,1})([A-Z]{1,1})([A-Z]{1,1})([a-z]{1,})$/ ) { #capture usernames in the native "FiMiLast" format
		my $capture_qq="$3$4$1$2";								#rewrite as LastFiMi
		push (@Last_FI_MI, $capture_qq);						#write to "LastFiMi" array

		my $capture_vv="$1$2$3$4";								#write as FiMiLast
		push (@FI_MI_Last, $capture_vv);						#write to "FiMiLast" array

	} elsif ( $_=~ m/^([A-Z]{1,1})([a-z]{1,})([A-Z]{1,1})([A-Z]{1,1})$/ ) { #capture native "LastFiMi" formatl
		my $capture_qq="$3$4$1$2";							#rewrite as FiMiLast
		push (@FI_MI_Last, $capture_qq);					#write to "FiMiLast" array

		my $capture_ww="$1$2$3$4";							#write LastFiMi format
		push (@Last_FI_MI, $capture_ww);					#write to "LastFiMi" array

	} elsif ( $_ =~ m/^([A-Za-z]{1,})\.([A-Za-z]{1,})$/i ) { 	#capture usernames in the native "first.last" format
		foreach my $alpha (@alpha) {							#generate usernames with middle intials
			my $capture_qq="$1\.$alpha\.$2";					#rewrite new format which includes all possible middle initials
			push (@first_dot_mi_dot_last, $capture_qq);			#write to "first.mi.last" array
			}	
		my $capture_vv="$1\.$2";							#write as first.last	
		push (@first_dot_last, $capture_vv);				#write to "first.last" array

	} elsif ( $_ =~ m/^([a-z]{1,})$/ ) { 					#capture usernames in the native all lowercase format (fimilast)
		my $capture_h=substr($1, 0, 1);						#capture the first letter
		my $capture_i=substr($1, 1, 1);						#capture the second letter
		my $capture_j=substr($1, 2);						#capture the remainder of the string
		my $capture_k="$capture_j$capture_h$capture_i";		#rewrite as last_fi_mi
		push (@Last_FI_MI, $capture_k);						#write to "last_fi_mi" to array
		push (@FI_MI_Last, $1);								#write to "fi_mi_last" array.

	} elsif ( $_ =~ m/^([A-Z]{1,})$/ ) { 					#capture usernames in the native all uppercase format (FIMILAST)
		my $capture_l=substr($1, 0, 1);						#capture the first letter
		my $capture_m=substr($1, 1, 1);						#capture the second letter
		my $capture_n=substr($1, 2);						#capture the remainder of the string
		my $capture_o="$capture_n$capture_l$capture_m";		#rewrite as "LastFiMi"
		my $capture_p="$capture_l$capture_m$capture_n";		#rewrite as "FiMiLast"
		push (@Last_FI_MI, $capture_o);						#write to the array
		push (@FI_MI_Last, $capture_p);						#write to "FiMiLast" array.

	} elsif ( $_ =~ m/^([a-z]{1,})\.([a-z]{1,1})\.([a-z]{1,})$/i ) {	#capture usernames in the "first.mi.last" format
		my $capture_p="$1\.$2\.$3";										#write "first.mi.last"
		my $capture_pp="$1\.$3";										#rewrite as "first.last"
		push (@first_dot_mi_dot_last, $capture_p);						#write to "first.mi.last" array
		push (@first_dot_last, $capture_pp);							#write to "first.last" array

	} elsif ( $_ =~ m/^([a-z]{1,})\,([\s]{0,})([a-z]{1,})$/i ) {		#cature usernames in the native "first,<sp>last" format
		foreach my $alpha (@alpha) {									#generate usernames with mi
			my $capture_qq="$1\.$alpha\.$3";							#rewrite new format
			push (@first_dot_mi_dot_last, $capture_qq);					#write to "first.mi.last" array
			}	
		my $capture_vv="$1\.$3";										#rewrite as first.last
		push (@first_dot_last, $capture_vv);							#write to "first.last" array

	} elsif ( $_ =~ m/^([MDrs]{2,3})\.\s([a-z]{1,})\s([a-z]{1,1})\.\s([a-z]{1,})$/i ) {	#capture usernames in the native "<MDrs>.<sp>first<sp>mi.<sp>last" format
		my $capture_qq="$2\.$3\.$4";											#rewrite as first.mi.last
		my $capture_vv="$2\.$4";												#rewrite as first.last
		push (@first_dot_mi_dot_last, $capture_qq);								#write to "first.mi.last" array
		push (@first_dot_last, $capture_vv);									#write to "first.last" array

	} elsif ( $_ =~ m/^([MDrs]{2,3})\.\s([a-z]{1,})\s([a-z]{1,})$/i ) {	#capture usernames in the native "<MDrs>.<sp>first<sp>last" format
		foreach my $alpha (@alpha) {									#generate usernames with mi
			my $capture_tt="$2\.$alpha\.$3";							#rewrite new format
			push (@first_dot_mi_dot_last, $capture_tt);					#write to "first.mi.last" array
			}	
		my $capture_ee="$2\.$3";										#rewrite as first.last
		push (@first_dot_last, $capture_ee);							#write to "first.last" array

	} else {
		push (@irregular, $_);											#write irregular names to an array
	}
}

#Create LastFiMi and FiMiLast variants for @first_dot_mi_dot_last array
foreach (@first_dot_mi_dot_last) {
	if ( $_ =~ m/^([a-z]{1,})\.([a-z]{1,1})\.([a-z]{1,})$/i ) { #capture usernames in the native "first<sp>mi.<sp>last" format
		my $capture_aaa="$1\.$2\.$3";												#rewrite as first.mi.last
		my $capture_bbb=substr($1, 0, 1);											#capture the first initial
		my $capture_ccc=substr($2, 0, 1);											#capture the middle initial
		my $capture_ddd="$3$capture_bbb$capture_ccc";									#rewrite as LastFiMi
		my $capture_eee="$capture_bbb$capture_ccc$3";									#rewrite as FiMiLast
		push (@Last_FI_MI, $capture_ddd);											#write to array
		push (@FI_MI_Last, $capture_eee);											#write to array
	}
}

##print username totals
print '[*]	The number of candidate usernames in the base array is: ' . scalar @base_array . "\n\n";
print '[*]	The number of usernames converted to the "first.last" format is: ' . scalar @first_dot_last . "\n\n";
print '[*]	The number of usernames converted to the "first.mi.last" format is: ' . scalar @first_dot_mi_dot_last . "\n\n";
print '[*]	The number of usernames converted to the "LastFiMi" format is: ' . scalar @Last_FI_MI . "\n\n";
print '[*]	The number of usernames converted to the "FiMiLast" format is: ' . scalar @FI_MI_Last . "\n\n";
if (@irregular) {
	print '[*]	The number of unprocessed usernames/lines is: ' . scalar @irregular . "\n\n";
	print "[*]	The following usernames/lines were not parsed\n\n";
	foreach my $schmutz (@irregular) {
		print "\t" . $schmutz;
	}
	print "\n";
}

##generate "first.last" variants 
foreach my $address (@first_dot_last) {
	chomp($address);
	my $product="${address}\@$domain";
	push (@domain, $product);
	my $product_ctr="${address}\.ctr\@$domain";
	push (@domain, $product_ctr);
	my $product_civ="${address}\.civ\@$domain";
	push (@domain, $product_civ);
	my $product_mil="${address}\.mil\@$domain";
	push (@domain, $product_mil);
}
 
##generate "first.mi.last" variants
foreach my $address (@first_dot_mi_dot_last) {
	chomp($address);
	my $product_fml="${address}\@$domain";
	push (@domain, $product_fml);
	my $product_fml_mil="${address}\.mil\@$domain";
	push (@domain, $product_fml_mil);
	my $product_fml_civ="${address}\.civ\@$domain";
	push (@domain, $product_fml_civ);
	my $product_fml_ctr="${address}\.ctr\@$domain";
	push (@domain, $product_fml_ctr);
}
 
##generate "LastFiMi@domain"
foreach my $address (@Last_FI_MI) {
	chomp($address);
	my $product_lfm="${address}\@$domain";
	push (@domain, $product_lfm);
}
 
##generate "FiMiLast@domain"
foreach my $address (@FI_MI_Last) {
	chomp($address);
	my $product_fml_2="${address}\@$domain";
	push (@domain, $product_fml_2);
}
 
#create file for writing
my $file = "email_enumeration.txt";

#Use the open() function to create the file handle.
unless(open FILE, '>'.$file) {
	# Die with error message 
	# if we can't open it.
	die "\nUnable to create $file\n";
}

#Remove duplicate values from the @aggregate_email array
my %hash   = map { $_ => 1 } @domain; #this statement uses the map function to create a hash containing key value pairs.The key is the email from the original array 
my @domain_email_unique = keys %hash; #The "keys" function will only display the unique keys from the set.  This statement writes them to a new array.
#To view the hash contents
#while ((my $key, my $value) = each(%hash)){
#     print $key.", ".$value."\n";
#}

# Write the emails to the file.
foreach my $item (@domain_email_unique) {
	print FILE "$item\n";
}

# close the file.
close FILE;

##print email totals
print '[*]	The number of unique email addresses generated is: ' . scalar @domain_email_unique . "\n\n";
print "[*]	All emails written to \"email_enumeration.txt\"\n\n";
print "[*]	Have a nice day\n\n";

sub help {
  print <<EOHELP;
  
email_generation_v003.pl By pjhartlieb at http://blogspot.pjhartlieb.com

		Usage: perl email_generation_v002.pl -f <filename> -d <domain>

Overview:
		Generate candidate email addresses for a specific domain given 
		a list of non-uniform domain names. 

Options:
	
		-help	This screen.
		-f 	Specifies text file containing usernames. One username per line. No
			trailing spaces
		-d	Specifies the domain used for email creation

Example:

		perl email_generation_v002.pl -f usernames.txt -d google.com
	 
EOHELP
exit;
}