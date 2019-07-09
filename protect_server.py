#! /usr/bin/python
import os, commands, sys
from urlparse import urlparse
from os.path import splitext

#Configurations
max_reads = 3
file_read = "/var/log/apache2/access.log"
file_ip_table = "/etc/"
white_list = ["127.0.0.1"]
white_exts = [".ico",".pdf",".flv",".jpg",".jpeg",".png",".gif",".js",".css",".swf",".xml",".txt",".htm",".html"]

#Temp variables
last_found = 0
last_ip = ""
last_time = ""

#Counter variables
n_bloqued_ips = 0

#Functions
def ipblocked( ip ):
    status, output = commands.getstatusoutput("iptables -L INPUT -v -n | grep '"+ip+"'")
    if output == "":
	return False
    else:
        return True

def get_ext(url):
    parsed = urlparse(url)
    root, ext = splitext(parsed.path)
    return ext

def die():
    sys.exit()

#Message welcome
print ("\n-----------------------")
print ("| PROTECT SERVER ALFA |")
print ("-----------------------\n")

#Open file log
infile = open(file_read, 'r')

#Read lines to check requests
for line in infile:
    frags = line.split(' ', 8)
    if get_ext(frags[6]) not in white_exts:
        if last_ip != frags[0]:
            last_ip = frags[0]
            last_time = frags[3]
            last_found = 0
        else:
            if frags[3] == last_time:
                last_found = last_found + 1

        if last_found >= max_reads and last_ip not in white_list and ipblocked(last_ip) == False:
	    #Block IP
            os.system("iptables -A INPUT -s "+last_ip+" -j DROP")
            print ("Blocked IP "+last_ip+"\n")
            n_bloqued_ips = n_bloqued_ips + 1

infile.close()

#Save table firewall with changes
if n_bloqued_ips:
    print ("Saving new table...\n")
    os.system("iptables-save")

#Finish
print ("\nFinish, "+str(n_bloqued_ips)+" IPs blocked\n")

