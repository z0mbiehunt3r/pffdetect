#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Fast-Fluxed domain detector (v0.8) - Try to detect if a domain is fast-fluxed
Based on https://pi1.informatik.uni-mannheim.de/filepool/research/publications/fast-flux-ndss08.pdf

Copyright (C) 2012  Alejandro Nolla Blanco - alejandro.nolla@gmail.com 
Nick: z0mbiehunt3r - @z0mbiehunt3r
Blog: navegandoentrecolisiones.blogspot.com


Thanks to:
Team Cymru for his awesome work (http://www.team-cymru.org/)
Buguroo and Ecija team!


"This product includes GeoLite data created by MaxMind, available from http://www.maxmind.com/."

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

'''
There goes the siren that warns of the air raid
Then comes the sound of the guns sending flak
Out for the scramble we've got to get airborne
Got to get up for the coming attack.
                        Iron Maiden - Aces High
'''

import argparse
import multiprocessing
import os
import re
import socket
import sys
import time
import urllib
import urllib2

try:
    import dns.resolver
    import dns.reversename
    dnspythoninstalled = True
except Exception, e:
    print str(e)
    print 'DNS method will be unavailable until you install dnspython (http://www.dnspython.org/)'
    dnspythoninstalled = False

try:
    from pygeoip import *  
    pygeoipinstalled = True
except:
    print str(e)
    print 'Geolite method will be unavailable until you install last version of pygeoip (https://github.com/appliedsec/pygeoip)'
    pygeoipinstalled = False
    

#----------------------------------------------------------------------
def __banner():
    banner = '''
        |----------------------------------------------------------|
        |                  Fast-Flux domain detector               |
        |               Alejandro Nolla (z0mbiehunt3r)             |
        |                                      Powered by Buguroo! |
        |----------------------------------------------------------|\n'''
    print banner


#----------------------------------------------------------------------
def __checkArgs():
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)
 
 
#----------------------------------------------------------------------
def checkDomain(domain, dnsserver, maxTTL, ASmethod, timeout, verbose=False):
    """
    Check if a given domain looks like a fast-fluxed one
    
    @param domain: Domain to check
    @type domain: str
    
    @param dnsserver: DNS dnsserver to ask to
    @type dnsserver: str
    
    @param maxTTL: Max TTL to consider a domains as fast-fluxed
    @type maxTTL: int

    @param ASmethod: Method to query Team Cymru
    @type ASmethod: str

    @param timeout: DNS timeout
    @type timeout: float

    @param verbose: Print info to screen
    @type verbose: bool

    @return: True if fast-fluxed, otherwise, returns false
    @rype: bool
    """
    
    if verbose: print "[*] Checking %s" %domain
    # Get A entries
    if verbose: print "[*] Retrieving DNS 'A' entries"
    a_records = __dnsGetARecords(domain, dnsserver, maxTTL, timeout)
    if not a_records:
        return 
    if verbose: print a_records
    
    # Get ASN
    if verbose: print "[*] Retrieving theirs autonomous systems"
    asn = []
    
    for record in a_records:
        if ASmethod == "DNS":
            if not dnspythoninstalled:sys.exit(-1)
            AS = __getASNumberUsingDNS(record, dnsserver, timeout)
        elif ASmethod == "HTTP":
            AS = __getASNumberUsingHTTP(record, False)
        elif ASmethod == "HTTPS":
            AS = __getASNumberUsingHTTP(record, True)
        elif ASmethod == "WHOIS":
            AS = __getASNumberUsingWHOIS(record)
        elif ASmethod == "geolite":
            if not pygeoipinstalled:sys.exit(-1)
            AS = __getASNumberUsingGeoLiteDatabase(record)
        asn.append(AS)
    if verbose: print asn
    
    # Get Flux Score
    flux_score = __getFluxScore(len(a_records), len(asn))
    if verbose: print "[*] %i flux score" %flux_score
    
    # Is fast-fluxed?
    fastfluxed = isFastFluxed(flux_score)
    if verbose: print fastfluxed
    
    return fastfluxed


#----------------------------------------------------------------------
def __dnsGetARecords(domain, server, maxTTL, timeout):
    """
    Get 'A' DNS entries for given domain and check TTL to discard no fast-fluxed domains, wait TTL and ask again
    
    @param domain: Domain to lookup
    @type domain: str
    
    @param server: DNS server to ask to
    @type server: str
    
    @param maxTTL: Maximum TTL to consider a domain as fast-fluxed
    @type maxTTL: int

    @param timeout: DNS query timeout
    @type timeout: float

    @return: List containing IPs for 'A' entries
    @rtype: list('192.168.1.100','127.0.0.1')
    """
    
    # Get TTL and DNS 'A' records
    ttl, records = __dnsLookup(domain, 'A', server, timeout)
    if not records:
        return False
    if ttl > maxTTL:
        print '[*] TTL too high to be a fast-fluxed domain'
        return False
    # Wait until cache expires
    time.sleep(ttl+1)
    # And ask again
    ttl, records2 = __dnsLookup(domain, 'A', server, timeout)
    if not records2:
        print '[!] Something went really bad with DNS query... :('
        return False
    records += records2
    
    return records


#----------------------------------------------------------------------
def __dnsLookup(domain, entry, server, timeout):
    """
    Makes a DNS lookup of given type
    
    @param domain: Domain to lookup
    @type domain: str
    
    @param entry: DNS entry to ask for (A/MX/NS)
    @type entry: str
    
    @param server: DNS server to ask to
    @type server: str
    
    @return: TTL for given domain and list containing IP entries
    @rtype: int, list
    """
    
    records = []
    
    try:
        # Create  DNS resolver object
        res = dns.resolver.Resolver()
        # Use just given DNS server
        res.nameservers = [server]
        res.lifetime = timeout
        answers = res.query(domain, entry)
        
        for rdata in answers:
            records.append(str(rdata))
            
    except Exception, e:
        if e.__doc__ == 'The operation timed out.':
            pass
        elif e.__doc__ == 'No non-broken nameservers are available to answer the query.':
            pass
        elif e.__doc__ == 'The response did not contain an answer to the question.':
            pass
        else:
            print e.__doc__
            raise e
        
        # Return 0 as TTL and no DNS entries
        return 0, False
    
    return answers.ttl, records
            

#----------------------------------------------------------------------
def __getASNumberUsingDNS(ipaddress, dnsserver, timeout):
    """
    Get Autonomous System number of given IP address using Team Cymru DNS service
    
    @param ipaddress: IP address to get his AS
    @type ipaddress: str
    
    @param dnsserver: DNS server to ask to
    @type dnsserver: str
    
    @param timeout: DNS timeout
    @type timeout: float
    
    @return The autonomous system number
    @rtype: int
    """
    
    # Reverse octets
    ipaddress = '.'.join(reversed(ipaddress.split('.')))
    
    # Query Team Cymru
    response = __dnsLookup(ipaddress+".origin.asn.cymru.com", 'TXT', dnsserver, timeout)
    # (14400, ['"3352 | 80.58.0.0/16 | ES | ripencc | 2001-06-13"'])
    autonomous_system = re.search("\"(\w+) \|", response[1][0])
    
    # Check if regex was successful
    if autonomous_system is not None:
        autonomous_system = autonomous_system.group(1)
    else:
        raise Exception(' Couldn\'t retrieve AS')
    
    return autonomous_system


#----------------------------------------------------------------------
def __getASNumberUsingWHOIS(ipaddress):
    """
    Get Autonomous System number of given IP address using Team Cymru WHOIS service
    
    @param ipaddress: IP address to get his AS
    @type ipaddress: str
    
    @return The autonomous system number
    @rtype: int
    """ 
    
    try:
        s = socket.socket()
        s.connect(("whois.cymru.com", 43))
        s.send(ipaddress+"\n")
        # Remove trailing line feed
        response = s.recv(1024).rstrip()
        asn = re.search("(\d+).+\|", response)
        # Check if regex was successful
        if asn is not None:
            asn = asn.group(1)
    except:
        raise
    
    return asn


#----------------------------------------------------------------------
def __getASNumberUsingHTTP(ipaddress, usessl):
    """
    Get Autonomous System number of given IP address using Team Cymru HTTP(S) service
    WARNING! If you REALLY need checking SSL certificate then use requests module
    http://docs.python-requests.org/en/latest/index.html
    
    @param ipaddress: IP address to get his AS
    @type ipaddress: str
    
    @param usessl: Use SSL
    @type ssl: bool
    
    @return The autonomous system number
    @rtype: int    
    """
    
    useragent = 'pffdetect/0.8 (http://code.google.com/p/pffdetect/)'
    url = 'asn.cymru.com/cgi-bin/whois.cgi'
    
    if usessl:
        url = 'https://'+url
    else:
        url = 'http://'+url
    
    # Cook headers and encode POST params
    headers = {'User-Agent': useragent}
    req = urllib2.Request(url, None, headers)
    params = urllib.urlencode(
        {'action': 'do_whois',
         'family':'ipv4',
         'method_whois':'whois',
         'bulk_paste':ipaddress,
         'submit_paste':'Submit'})
    
    try:
        # Make request
        f = urllib2.urlopen(req, params)    
        response = f.read()
        f.close()
        
        # Extract AS number only
        # 15169   | 8.8.8.8          | GOOGLE - Google Inc.
        regex = re.search('(\d+)\s+\|\s+%s'%ipaddress, response)
        if regex is not None:
            asnumber = regex.group(1)
        else:
            asnumber = False
    except:
        pass
    
    return asnumber



#----------------------------------------------------------------------
def __getASNumberUsingGeoLiteDatabase(ipaddress):
    """
    Get Autonomous System number of given IP address using local MaxMind Geo Lite database
    
    @param ipaddress: IP address to get his AS
    @type ipaddress: str
    
    @return The autonomous system number
    @rtype: int    
    """
    
    # Taken from http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
    database = './geoliteasn/GeoIPASNum.dat'
    try:
        gi = GeoIP(database)
    except Exception, e:
        if e.strerror == 'No such file or directory':
            print '[!] Error - do you have a local copy of MaxMind GeoLite database?'
        else:
            print str(e)
        sys.exit()
    # 'AS15169 Google Inc.'
    organization = gi.org_by_addr(ipaddress)
    regex = re.search('AS(\d+)', organization)
    
    if regex is not None:
        asnumber = regex.group(1)
    else:
        asnumber = False
    
    return asnumber

#----------------------------------------------------------------------
def __getFluxScore(nA, nASN):
    """
    Calculate 'Flux Score'
    
    @param nA: Number of unique DNS 'A' entries
    @type nA: int
    
    @param nASN: Number of unique Autonomous System for these IP addresses
    @type nASN: int
    
    @return: Flux Score 
    @rtype: float
        (Read https://pi1.informatik.uni-mannheim.de/filepool/research/publications/fast-flux-ndss08.pdf for more info)
    """
    
    w_1 = 1.32
    w_2 = 18.54
    flux_score = w_1*nA + w_2*nASN
    
    return flux_score


#----------------------------------------------------------------------
def isFastFluxed(flux_score):
    """
    Return true or false based on flux_score
    
    @param flux_score: Calculated flux score
    @type flux_score: float
    
    @return: True if fast-fluxed, False otherwise
    @rtype: bool
    """
    
    # (Read https://pi1.informatik.uni-mannheim.de/filepool/research/publications/fast-flux-ndss08.pdf for more info)
    b = 142.38
    
    if flux_score - b > 0:
        return True
    else:
        return False


#----------------------------------------------------------------------
def __readDomains(file):
    """
    Read domains from given file
    
    @param file: File with domains
    @type file: str
    
    @return: List of domains
    @rtype: list('www.domain1.com', 'www.domain2.gov')
    """
    
    # To avoid some weir errors
    if os.path.exists(file) and os.path.isfile(file):
        try:
            fd = open(file, "r")
            domains = fd.readlines()
            fd.close()
            # Remove trailing
            domains = map(str.rstrip, domains)
        except Exception, e:
            raise e

    else:
        raise Exception('I/O Error')
    
    return domains


#----------------------------------------------------------------------
def checkDomains(domains, dnsserver, maxTTL, method, timeout, processes, verbosity=False):
    """
    Check a list of domains to looks if looks like a fast-fluxed one
    
    @param domains: Domains to check
    @type domains: list('www.domain1.com', 'www.domain2.org')
    
    @param dnsserver: DNS dnsserver to ask to
    @type dnsserver: str
    
    @param maxTTL: Max TTL to consider a domains as fast-fluxed
    @type maxTTL: int

    @param ASmethod: Method to query Team Cymru
    @type ASmethod: str

    @param timeout: DNS timeout
    @type timeout: float

    @param processes: Number of processes to use paralelized
    @type domain: int

    @param verbose: Print info to screen
    @type verbose: bool
    
    @return: List with fast-fluxed domains
    @rtype: list('www.fastfluxed.com','www.fastfluxed.ru')
    """
    
    # Mutable list to store domains to check
    m_domains_input = multiprocessing.Manager().list()
    m_domains_input.extend(domains)
    
    # Mutable list to store fast-fluxed domains
    m_fastfluxed_output = multiprocessing.Manager().list()
    
    # Pool of processes
    m_pool = multiprocessing.Pool(processes)
   
    # Create processes and start working!
    for p in range(processes):
        m_pool.apply_async(__checkDomainsWorker, (m_domains_input, m_fastfluxed_output,dnsserver, maxTTL, method, timeout, verbosity))
   
    # Wait until all domains have been processed
    m_pool.close()
    m_pool.join()
    
    return m_fastfluxed_output


#----------------------------------------------------------------------
def __checkDomainsWorker(m_domains_input, m_fastfluxed_output, dnsserver, maxTTL, method, timeout, verbosity=False):
    """
    Check if a given domain looks like a fast-fluxed one
    
    @param domains: Domains to check
    @type domains: list('www.domain1.com', 'www.domain2.org')
    
    @param dnsserver: DNS dnsserver to ask to
    @type dnsserver: str
    
    @param maxTTL: Max TTL to consider a domains as fast-fluxed
    @type maxTTL: int

    @param ASmethod: Method to query Team Cymru
    @type ASmethod: str

    @param timeout: DNS timeout
    @type timeout: float

    @param verbose: Print info to screen
    @type verbose: bool
    """
    
    try:
        while len(m_domains_input) > 0:
            # Take a domain from list
            domain = m_domains_input.pop()
            
            # Check if fast-fluxed
            fastfluxed = checkDomain(domain, dnsserver, maxTTL, method, timeout, verbosity)
            if fastfluxed:
                m_fastfluxed_output.append(domain)
        
    except KeyboardInterrupt:
        print 'Ctrl^C - killing process...'
        return
        

if __name__ == '__main__':   
    __banner()
   
    
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', dest='domain', action='store', help='domain to check')
    group.add_argument('-f', '--file', dest='file', action='store', help='list of domains to check')
    
    group2 = parser.add_argument_group()
    group2.add_argument('-s', '--server', dest='server', action='store', help='dns server to use', required=True)
    group2.add_argument('-m', '--method', dest='method', action='store', help='method to query Team-Cymru IP2ASn service (default DNS)', default="DNS", choices=["DNS","WHOIS", "HTTP", "HTTPS", "geolite"])
    group2.add_argument('-p', '--processes', dest='processes', action='store', type=int, help='number of process to use (default one per core)', default=multiprocessing.cpu_count())
    group2.add_argument('-t', '--timeout', dest='timeout', action='store', type=float, help='timeout for DNS queries (default 2 sec)', default=2)
    # Warning, things are changing....    
    group2.add_argument('--ttl', dest='maxTTL', action='store', type=int, help='maximum TTL to consider a domain as fast-fluxed (default 1800 sec)', default=1800)    
    group2.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False)
    
    
    __checkArgs()
    
    
    args = parser.parse_args()
    
    try:
        # Have a domain to check?
        if args.domain:
            print "[*] Checking if %s is a fast-fluxed domain (could take a while depending on domain TTL)" %args.domain
            if checkDomain(args.domain, args.server, args.maxTTL, args.method, args.timeout, args.verbose):
                print "   [!] Domain %s is fast-fluxed" %args.domain
            else: 
                print "   [-] Domain %s is not fast-fluxed" %args.domain
        
        # Or a bunch of them?
        elif args.file:
            domains = __readDomains(args.file)
            print "[*] Checking a bunch of domains {%i} (could take a while depending on domains TTL)" %len(domains)
            print "[*] Using %i processes" %args.processes 
            
            fastfluxed = checkDomains(domains, args.server, args.maxTTL, args.method, args.timeout, args.processes, args.verbose)
            for domain in fastfluxed:
                print "   [!] Domain %s is fast-fluxed" %domain
        
        print "[-] Done"
    
    except KeyboardInterrupt:
        print 'Exiting...'
        sys.exit(-1)        