#!/usr/bin/python3 
#ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with malware with the infosec community, AV vendors and threat intelligence providers

#Importing required modules
from datetime import datetime, timedelta
import time
import urllib3
import requests
import json
import re
import os
import csv


#Set date time
today = datetime.today()
format_today = today.strftime("%Y-%m-%d")


#Download recent IOC JSON
print(20 * "--")
print(f"[*] Downloading recent IOC json file - {format_today}")

url = 'https://threatfox.abuse.ch/export/json/recent/'
local_file = 'threatfox_ioc.json'
data = requests.get(url)
if data.status_code == 200:
	with open(local_file, 'wb') as file:
		file.write(data.content)
		file.close()
	print(f'[*] {local_file} successfully downloaded')
else:
	print("[!!!] Download Failed check connection to ThreatFox")


#Deserializing JSON to work in python
with open(f'{local_file}') as python_obj:
	data = json.load(python_obj)

ioc_list = []
#print(type(data))
for x in data.values():
	for value in x:
		ioc_list.append(value['ioc_value'])

print(f"[*] {len(ioc_list)} IOC's Collected")


#Extract IoC to new lists
Abusech_Botnet_IP = []
Abusech_MalwareSites = []
Abusech_MalwareHashes = []

#Defining regex ioc patterns
regex_md5 = re.compile(r'^[A-Fa-f0-9]{32}$')
regex_sha1 = re.compile(r'^[A-Fa-f0-9]{40}$')
regex_sha256 = re.compile(r'^[A-Fa-f0-9]{64}$')
regex_url = re.compile(r'^((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')
regex_ip = re.compile(r'^\b(?:\d{1,3}\.){3}\d{1,3}\b')


#function to extract each ioc to new list
def extract_iocs(ioc):
	print("[*] Grouping IP's, Hashes and URL's")
	for i in ioc:
		if (re.search(regex_md5, i)):
			Abusech_MalwareHashes.append(i)
		elif (re.search(regex_sha1, i)):
			Abusech_MalwareHashes.append(i)
		elif (re.search(regex_sha256, i)):
			Abusech_MalwareHashes.append(i)
		elif (re.search(regex_url, i)):
			Abusech_MalwareSites.append(i)
		elif re.findall(regex_ip,i):
			#splitting IP from port
			ip, port = re.split(':', i)
			Abusech_Botnet_IP.append(ip)

		
extract_iocs(ioc_list)
print(f"[*] {len(Abusech_MalwareHashes)} Total hash formats found")
print(f"[*] {len(Abusech_MalwareSites)} Total URI found")
print(f"[*] {len(Abusech_Botnet_IP)} Total IP's found")


csv_file = "latest_iocs.csv"

def write_to_csv(iocs):
	with open(f'{csv_file}', 'a') as myfile:
	    wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
	    for ioc in iocs:
	        wr.writerow([ioc])
print(f'[*] All IoC extracted to {csv_file}')	        
print(20 * "--")

write_to_csv(Abusech_Botnet_IP)
write_to_csv(Abusech_MalwareSites)
write_to_csv(Abusech_MalwareHashes)
	
