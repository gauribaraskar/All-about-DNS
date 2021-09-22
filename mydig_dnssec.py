#!/usr/bin/env python
# coding: utf-8

# In[1]:


import sys
import dns.message
import dns.query
import time
import os


# Root server configuration
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



# Function to get a single query response from a server
def resolve_from_server(hostname,rdtype,server):
    query = dns.message.make_query(hostname, rdtype, want_dnssec=True)
    try:
        response = dns.query.udp(query, server, timeout=5)
        return response
    except Exception as e:
        raise e



def verify_zone(name,dnskey_response_child,authority_section):
    rrsig = None
    ds = None
    name = None
    for rr in authority_section:
        if rr.rdtype==rdtypeToDNSPythonMap['DS']:
            ds = rr
            break
    name = authority_section[0].name
    if ds is None:
        print("Zone not DNS sec enabled!")
        sys.exit()
    algo = ds[0].digest_type
    #print("ALGOOOO",algo)
    if (ds[0].digest_type == 1):
        algo = "sha1"
    elif (ds[0].digest_type == 2):
        algo = "sha256"
    if ds is None:
        print("DNSSEC not enabled in zone!")
        sys.exit()
    dnskey = get_dns_key(dnskey_response_child)
    child_hash = dns.dnssec.make_ds(name,dnskey,algo)
    #print("Equal hash? ",child_hash==ds[0])
    return child_hash==ds[0]
    


# In[282]:


def is_ds_record_available(section):
    for rrset in section:
        if rrset.rdtype==rdtypeToDNSPythonMap['DS']:
            return rrset
    return None


# In[283]:


def verify_records(response,rdtype,name):
    print("Verifying records for type ",rdtype)
    return verify_rrset(response,rdtype,name)


# In[284]:


def resolve_iteratively(hostname,response,response_parent,rdtype):
    if len(response.answer)>0:
        records = []
        for r in response.answer:
            noRecords = True
            for rr in r:
                if(rr.rdtype==rdtypeToDNSPythonMap[rdtype]):
                    dns_key = resolve_from_server(response.answer[0].name,'DNSKEY',response_parent.additional[0][0].to_text())
                    if(verify_records(response,rdtype,response.answer[0].name) and verify_zone(response.answer[0].name,dns_key,response_parent.authority)):
                        noARecord = False
                        records.append(rr.to_text())
            if(noRecords):
                for rr in r:
                    cnames = []
                    cname_records = []
                    if(rr.rdtype==rdtypeToDNSPythonMap['CNAME']):
                        cnames.append(rr.to_text())
                for cname in cnames:
                    records_from_cname = main(cname,rdtype)
                    if(len(records_from_cname)>0):
                        records = records_from_cname
            return records
    elif len(response.additional)>0:
        if is_ds_record_available(response.authority) is not None:
            ips = []
            for r in response.additional:
                for rr in r:
                    if(rr.rdtype==rdtypeToDNSPythonMap['A']):
                        ips.append(rr.address)
            for ip in ips:
                dnskey_response = resolve_from_server(str(response.authority[0].name),'DNSKEY',ip)
                if(verify_records(response,rdtype,response.authority[0].name)):
                    if(verify_zone(response.authority[0].name,dnskey_response,response.authority)):
                        response_subdomain = resolve_from_server(hostname,rdtype,ip)
                        if response_subdomain is not None:
                            return resolve_iteratively(hostname,response_subdomain,response,rdtype)
                        else:
                            continue
                    else:
                        print("Zone could not be verified!")
                        sys.exit()
        else:
            print("DNSSEC not enabled on zone!")
            sys.exit()
    elif len(response.authority)>0:
        if is_ds_record_available(response.authority) is not None: 
            nss = []
            for r in response.authority:
                for rr in r:
                    if rr.rdtype==rdtypeToDNSPythonMap['NS']:
                        nss.append(rr.target)
            for ns in nss:
                ips = main(ns,rdtype)
                if(len(ips)>0):
                    final_ips = []
                    for ip in ips:
                        if(verify_records(response,rdtype,response.authority[0].name)):
                            if(verify_zone(response.authority[0].name,dnskey_response,response.authority)):
                                dnskey_response = resolve_from_server(str(response.authority[0].name),'DNSKEY',ip)
                                response2 = resolve_from_server(hostname,rdtype,ip)
                                final_ips = resolve_iteratively(hostname,response2,response,rdtype)
                                if final_ips is not None:
                                    return final_ips
                                else:
                                    continue
                            else:
                                print("DNS Zone could not be verified!")
                                sys.exit()
                        else:
                            print("DNS records could not be verified!")
                            sys.exit()
                else:
                    print("No nameserver found!")
                    sys.exit()
        else:
            print("DNSSEC not enabled on zone!")
            sys.exit()
    else:
        raise Exception 


# In[285]:


def main(hostname,rdtype):
    for server in root_servers:
        dnskey_response = resolve_from_server('.','DNSKEY',server)
        if(verify_dns_key(dnskey_response) and verify_root(dnskey_response)):
            response = resolve_from_server(hostname,rdtype,server)
            response_final = resolve_iteratively(hostname,response,response,rdtype)
            if(response_final):
                return response_final
    return None


# In[286]:


rdtypeToDNSPythonMap = {
    'RRSIG': dns.rdatatype.RRSIG,
    'DNSKEY': dns.rdatatype.DNSKEY,
    'A': dns.rdatatype.A,
    'NS': dns.rdatatype.NS,
    'MX': dns.rdatatype.MX,
    'CNAME': dns.rdatatype.CNAME,
    'DS': dns.rdatatype.DS
}


# In[287]:


def verify_dns_key(response):
    try:
        dns.dnssec.validate(response.answer[0],response.answer[1],{response_dns_key.answer[0].name:response.answer[0]})
    except dns.dnssec.ValidationFailure:
        print("DNS keys could not be verified!")
        raise e
    finally:
        #print("WORKED!")
        return True


# In[288]:


def verify_rrset(response,rdtype,zsk):
    try:
        dns.dnssec.validate(response.answer[0],response.answer[1],{response.answer[0].name:response.answer[0]})
    except dns.dnssec.ValidationFailure:
        print("Signatures didnt match!")
        raise e
    finally:
        #print("WORKED!")
        return True  


# In[289]:


def get_pub_key(response):
    dnskey = None
    for rrset in response.answer:
        for r in rrset:
            if r.rdtype==dns.rdatatype.DNSKEY and r.flags == 257:
                dnskey = r
                return dnskey
                break
    return None


# In[290]:


def get_dns_key(response):
    dnskey = None
    for rrset in response.answer:
        for r in rrset:
            if r.rdtype==dns.rdatatype.DNSKEY and r.flags == 257:
                dnskey = r
                return dnskey
                break
    return None


# In[291]:


root_anchors = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5', '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']

def verify_root(dnskey_response):
    dnskey = get_dns_key(dnskey_response)
    for root_anchor in root_anchors:
        child_hash = dns.dnssec.make_ds('.',dnskey,'SHA256')
        if child_hash.to_text() == root_anchor:
            return True
            break
    return False


# In[292]:


main("dnssec-failed.org","A")


# In[ ]:





# In[ ]:





# In[ ]:




