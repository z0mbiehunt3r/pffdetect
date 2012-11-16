pffdetect
==========

pffdetect is a simple python script to check if a given domain, or list of them, looks like fast-fluxed domain. Can also be easily used as an external python module.

**WARNING**: A positive result doesn't mean that is fast-fluxed, only that it **looks like** fast-fluxed domains. (Have in mind thinks like GSLB, multiple IPS, and so).

It's based on https://pi1.informatik.uni-mannheim.de/filepool/research/publications/fast-flux-ndss08.pdf paper written by Thorsten Holz,Christian Gorecki, Konrad Rieck and Felix C. Freiling.

To check AS number of an IP address it uses Team Cymru's service IP TO ASN MAPPING (http://www.team-cymru.org/Services/ip-to-asn.html) and support following methods:

* Whois
* DNS
* HTTP(S)
* Local database (http://www.maxmind.com/app/asnum)

![alt text](http://i45.tinypic.com/34r7mo9.jpg")

Thanks to:
* Original researchers
* Écija and buguroo team
* Team Cymru
* MaxMind
