# Run this script if you are a Windows user and npcap is not installed. 
# The scapy module relies on it to work properly.

import os, urllib.request

def download_npcap():
  url = "https://npcap.com/dist/npcap-1.80.exe"
  installer_path = "npcap-180.exe"
  urllib.request.urlretrieve(url, installer_path)
  os.system(installer_path)

if __name__ == "__main__":
  download_npcap()