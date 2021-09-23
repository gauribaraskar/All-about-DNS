# CSE 534 - Assignment 1
## All-about-DNS

External Libraries used 

* dnspython 
* numpy
* pandas

Files
* mydig.py - DNS resolver using stub resolver
* mydig_dnssec.py - DNSSEC resolver using stud resolver
* dnsscript.sh - bash script to run DNS resolver. Additonal arguments for enabling DNSSEC can be specified here like '-dnssec'
* performance.pdf - This is the PDF for part C of the assignment where we compare the performance of mydig against local DNS server and Google server
* output.txt - This file contains the output for mydig.py. It lists examples along with the expected output.
* dnssec_implementation.pdf - This PDF explains the code for implementation of DNSSEC.
* requirements.txt - requirements.txt file for runninf the source code

Usage
* cd to the source folder
* run **pip install -r /path/to/requirements.txt**
* run bash script dns_script.sh using any of the following commands based on the platform
  1. Windows - bash dns_script.sh (-dnssec) <domain_name> <record_type>
  2. Linux - sh dns_script.sh (-dnssec) <domain_name> <record_type>
  3. Mac - sh dns_script.sh (-dnssec) <domain_name> <record_type>
* To see usage run - sh dns_script.sh -h 

