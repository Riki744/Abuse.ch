#Downloads C2 IP Blocklist and adds them to csv (Dridex, Heodo (aka Emotet), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor))
#Import required modules

import wget
import os
import csv
import re
import pandas as pd  
from datetime import datetime, timedelta

today = datetime.today()
format_today = today.strftime("%Y-%m-%d")


#Downloading latest blocklist
print(20 * "--")
print(f"Downloading latest C2 IP blocklist: {format_today}")
file = wget.download(f"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
print(f"{file} downloaded")
print(20 * "--")

#Formating .txt file to import it in csv
with open(f"{file}", 'r') as f:
	text = f.read()

	
ips = []
#regex for ip
regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text)

if regex is not None:
    for match in regex:
        if match not in ips:
            ips.append(match)
number_of_ips = len(ips)



csv_batch = f"{format_today}_C2_IP.csv"
df = pd.DataFrame(ips)
df.to_csv(csv_batch, index=False)


print(f"Extracted: {number_of_ips} IPs to {csv_batch}")
print(20 * "--")
