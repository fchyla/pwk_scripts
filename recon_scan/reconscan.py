#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Orignal script author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
## [Modified by]: Filip Chyla (keresh)
## - removed hardcoded directories
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such
## as smb, smtp, snmp, ftp and other.
##-------------------------------------------------------------------------------------------------------------
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's
## worth anything anyway :)
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return


def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script
       subprocess.call(SCRIPT, shell=True)
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN %s/%s_http.nmap %s" % (port, scan_results_location, ip_address, scan_results_location, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oX %s/%s_https.nmap %s" % (port, scan_results_location, ip_address, scan_results_location, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX results/exam/nmap/%s_mssql.xml %s" % (port, scan_results_location, ip_address, scan_results_location, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on " + ip_address + ":" + port
    SCRIPT = "./snmprecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
    return

def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on " + ip_address + ":" + port
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP nmap scans for " + ip_address
   serv_dict = {}
   TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '%s/%s.nmap' -oX '%s/nmap/%s_nmap_scan_import.xml' %s"  % (scan_results_location, ip_address, scan_results_location, ip_address, ip_address)
   UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/%sU.nmap' -oX '%s/nmap/%sU_nmap_scan_import.xml' %s" % (scan_results_location, ip_address, scan_results_location, ip_address, ip_address)
   results = subprocess.check_output(TCPSCAN, shell=True)
   udpresults = subprocess.check_output(UDPSCAN, shell=True)
   lines = results.split("\n")
   for line in lines:
      ports = []
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
	 while "  " in line:
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
	 port = line.split(" ")[0] # grab the port/proto
         if service in serv_dict:
	    ports = serv_dict[service] # if the service is already in the dict, grab the port list

         ports.append(port)
	 serv_dict[service] = ports # add service to the dictionary along with the associated port(2)

   # go through the service dictionary to call additional targeted enumeration functions
   for serv in serv_dict:
      ports = serv_dict[serv]
      if (serv == "http"):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)
      elif (serv == "ssl/http") or ("https" in serv):
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpsEnum, ip_address, port)
      elif "ssh" in serv:
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(sshEnum, ip_address, port)
      elif "smtp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smtpEnum, ip_address, port)
      elif "snmp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(snmpEnum, ip_address, port)
      elif ("domain" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(dnsEnum, ip_address, port)
      elif ("ftp" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(ftpEnum, ip_address, port)
      elif "microsoft-ds" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smbEnum, ip_address, port)
      elif "ms-sql" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)

   print "INFO: TCP/UDP Nmap scans completed for " + ip_address
   return

# grab the discover scan results and start scanning up hosts
print "############################################################"
print "####                      RECON SCAN                    ####"
print "####            A multi-process service scanner         ####"
print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
print "############################################################"

alive_hosts = str(raw_input('Live hosts file: '))
scan_results_location = str(raw_input('Where to drop the results? '))

#Check if scan_results_location exists if not create

if not os.path.exists(scan_results_location):
    os.makedirs(scan_results_location)

if not os.path.exists(scan_results_location+'/nmap'):
    os.makedirs(scan_results_location+'/nmap')

if __name__=='__main__':
   f = open(alive_hosts, 'r') # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
   for scanip in f:
       jobs = []
       p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       jobs.append(p)
       p.start()
   f.close()
