#!/usr/bin/python

############################################################
#                                                          #
#                                                          #
#     [*] Retrieving website data from Censys              #
#                                                          #
#                                                          #
#     [*] 2017.12.12                                       #
#          V0001                                           #
#          Black Lantern Security (BLS)                    #
#          @pjhartlieb                                     #
#                                                          #
#                                                          #
############################################################


import censys.certificates

UID = "<uid>"
SECRET = "<secret>"

websites = censys.websites.CensysWebsites(UID, SECRET)
#fields = ["parsed.subject_dn", "parsed.fingerprint_sha256", "parsed.fingerprint_sha1"]

for c in websites.search("443.https_www.tls.certificate.parsed.names:/.*keyword.*/"):
    print c["443.https_www.tls.certificate.parsed.names"]
