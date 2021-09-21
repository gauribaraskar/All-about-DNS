#!/usr/bin/env python
# coding: utf-8


'''Import all modules'''
import sys
import dns.message
import dns.query
import time
import pandas as pd
import numpy as np
import datetime


'''Configuration parameters'''
root_servers = [
    '198.41.0.4',
    '199.9.14.201',
    '192.33.4.12',
    '199.7.91.13',
    '192.203.230.10',
    '192.5.5.241',
    '192.112.36.4',
    '198.97.190.53',
    '192.36.148.17',
    '192.58.128.30',
    '193.0.14.129',
    '199.7.83.42',
    '202.12.27.33'
]

timeout = 1

local_dns_server = [
    '8.8.8.8'
]
rdata_type_map = {
    'A': dns.rdatatype.A,
    'NS': dns.rdatatype.NS,
    'MX': dns.rdatatype.MX,
    'CNAME': dns.rdatatype.CNAME
}


class MetaData:
    def __init__(self,time,size):
        self.time = time
        self.size = size


'''Function to fetch records from root DNS servers'''
def resolve_from_root(hostname,rdtype):
    query = dns.message.make_query(hostname, rdtype)
    for server in root_servers:
        server_response = resolve_from_server(hostname,rdtype,server)
        if server_response:
            return server_response
        else:
            continue



'''Function to fetch records from NS'''
def resolve_from_server(hostname,rdtype,server):
    print(hostname,rdtype,server)
    query = dns.message.make_query(dns.name.from_text(str(hostname)), rdtype)
    try:
        response = dns.query.udp(query, server, timeout=5)
        return response
    except Exception as e:
        raise e


''' Recursive function to get records'''
def resolve_iteratively(hostname,rdtype,response: [dns.message.Message]):
    if len(response.answer)>0:
        records = []
        for r in response.answer:
            noRecords = True
            for rr in r:
                if(rr.rdtype==rdata_type_map[rdtype]):
                    noARecord = False
                    records.append(rr.to_text())
            if(noRecords):
                for rr in r:
                    cnames = []
                    cname_records = []
                    if(rr.rdtype==rdata_type_map['CNAME']):
                        cnames.append(rr.to_text())
                for cname in cnames:
                    records_from_cname = main_helper(cname,rdtype)
                    if(len(records_from_cname)>0):
                        records = records_from_cname
            return records
    elif len(response.additional)>0:
        ips = []
        for r in response.additional:
            for rr in r:
                if(rr.rdtype==dns.rdatatype.A):
                    ips.append(rr.address)
        for ip in ips:
            response_subdomain = resolve_from_server(hostname,rdtype,ip)
            if response_subdomain is not None:
                return resolve_iteratively(hostname,rdtype,response_subdomain)
            else:
                continue
    elif len(response.authority)>0:
        nss = []
        for r in response.authority:
            for rr in r:
                nss.append(rr.target)
        for ns in nss:
            ips = main_helper(ns,rdtype)
            if(len(ips)>0):
                final_ips = []
                for ip in ips:
                    response2 = resolve_from_server(hostname,rdtype,ip)
                    final_ips = resolve_iteratively(hostname,rdtype,response2)
                    if final_ips is not None:
                        return final_ips
                    else:
                        continue
    else:
        raise Exception 



def print_like_dig(hostname,rdtype,records,metadata):
    print(';;QUESTION SECTION:')
    print(hostname + "     " + "IN    " + rdtype)
    print("\n")
    print(';;ANSWER SECTION:')
    for record in records:
        print(hostname + "     " + "IN    " + rdtype + "    " + record)
    print("\n")
    print('Query time: ' + str(int(metadata.time * 1000)) + ' msec')
    print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    print('MSG SIZE rcvd: ', metadata.size, '\n')




def main_helper(hostname,rdtype):
    rr = None
    for server in root_servers:
        response = resolve_from_server(hostname,rdtype,server)
        if response is not None:
            rr = resolve_iteratively(hostname,rdtype,response)
            break
    return rr



def main(hostname,rdtype):
    now = datetime.datetime.now()
    start = time.time()
    records = main_helper(hostname,rdtype)
    total_time = time.time() - start
    size = sys.getsizeof(records)
    print_like_dig(hostname,rdtype,records,MetaData(total_time,size))
    return total_time



if __name__ == '__main__':
    domain = sys.argv[1]
    if sys.argv[2] is not None:
        rdtype = sys.argv[2]
    else:
        rdtype = 'A'
    rdtype = rdtype.upper()
    domain = domain.replace("https://www.", "");
    domain = domain.replace("http://www.", "");
    domain = domain.replace("www.", "");
    main(domain,rdtype)
