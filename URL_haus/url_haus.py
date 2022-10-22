#!/usr/bin/python3 
# URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution

#Import required modules
from datetime import datetime, timedelta
import wget
import urllib3
import requests
import os
import re
import csv


#Set date time
today = datetime.today()
format_today = today.strftime("%Y-%m-%d")

try:
	#Download hostfile Domain names only
	print(20 * "--")
	print(f"[*] Downloading hostfile from Abuse.ch - {format_today}")

	url = 'https://urlhaus.abuse.ch/downloads/hostfile/'
	local_file = 'url_house.txt'
	data = requests.get(url)

	#Saving data in local_file
	print(f'[*] Writing content to {local_file}')

	with open(local_file, 'wb') as file:
		file.write(data.content)
		file.close()
except:
	print("[!!!] Failed to download malware url's from Abuse.ch")

#Setting Regex for valid domains
regex = '^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}'
p = re.compile(regex)

DNS = []

#Extracting only domain names with regex
print(f'[*] Extracting domain names from {local_file}')
with open(local_file) as file:
	for line in file.readlines():
		whitespace = line.strip()
		localhost = whitespace.strip("127.0.0.1")
		final = localhost.strip()
		if (re.search(p, final)):
			DNS.append(final)

items = len(DNS)
print(f"[*] Extracted {items} valid malware distributed domain sites")

csv_file = "malware_sites.csv"
file_check = os.path.exists(f'{csv_file}')


if file_check == False:
	#Writing DNS list to csv
	print(f"[*] Writing Malware DNS to {csv_file}")
	with open(f'{csv_file}', 'w', ) as myfile:
	    wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
	    for name in DNS:
	        wr.writerow([name])
	print(20 * "--")
else:
	print(f"[!!!] File with name {csv_file} already exists, check existing file!")
