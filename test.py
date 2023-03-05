import http.client
import json
from lxml import *
from json2xml import json2xml
from json2xml.utils import *

from setuptools import Command

conn = http.client.HTTPConnection("139.144.2.110:80")

# {
#     "nmap": {
#         "command_line": "nmap -oX - -Pn -sV -T4 -O -F 127.0.0.1",
#         "scaninfo": {
#             "tcp": {
#                         "method": "syn",
#                         "services": "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
#             }
#         },
#         "scanstats": {
#             "timestr": "Sat Oct  1 04:14:15 2022",
#             "elapsed": "2.01",
#             "uphosts": "1",
#             "downhosts": "0",
#             "totalhosts": "1"
#         }
#     },
#     "scan": {
#         "127.0.0.1": {
#             "hostnames": [
#                 {
#                     "name": "localhost",
#                     "type": "PTR"
#                 }
#             ],
#             "addresses": {
#                 "ipv4": "127.0.0.1"
#             },
#             "vendor": {},
#             "status": {
#                 "state": "up",
#                 "reason": "user-set"
#             },
#             "uptime": {
#                 "seconds": "1849818",
#                 "lastboot": "Fri Sep  9 18:23:57 2022"
#             },
#             "tcp": {
#                 "22": {
#                     "state": "open",
#                     "reason": "syn-ack",
#                     "name": "ssh",
#                     "product": "OpenSSH",
#                     "version": "8.4p1 Debian 5+deb11u1",
#                     "extrainfo": "protocol 2.0",
#                     "conf": "10",
#                     "cpe": "cpe:/o:linux:linux_kernel"
#                 }
#             },
#             "portused": [
#                 {
#                     "state": "open",
#                     "proto": "tcp",
#                     "portid": "22"
#                 },
#                 {
#                     "state": "closed",
#                     "proto": "tcp",
#                     "portid": "7"
#                 },
#                 {
#                     "state": "closed",
#                     "proto": "udp",
#                     "portid": "36284"
#                 }
#             ],
#             "osmatch": [
#                 {
#                     "name": "Linux 2.6.32",
#                     "accuracy": "100",
#                     "line": "55543",
#                     "osclass": [
#                         {
#                             "type": "general purpose",
#                             "vendor": "Linux",
#                             "osfamily": "Linux",
#                             "osgen": "2.6.X",
#                             "accuracy": "100",
#                             "cpe": [
#                                 "cpe:/o:linux:linux_kernel:2.6.32"
#                             ]
#                         }
#                     ]
#                 }
#             ]
#         }
#     }
# }

payload = ""

conn.request("GET", "/api/p1/admin:passwd/127.0.0.1", payload)

res = conn.getresponse()
data = res.read()
final = json.loads(data)

# root = ET.Element("nmap")
# root2= ET.Element("scan")
# command_line = ET.SubElement(root, "command_line")
# scaninfo = ET.SubElement(root, "scaninfo")
# scanstats = ET.SubElement(root, "scanstats")
# target = ET.SubElement(root2, "127.0.0.1")
# tree = ET.ElementTree(root,root2)
# tree.write("nmap-test.xml")

xml_data = json2xml.Json2xml(final).to_xml()
print(xml_data)