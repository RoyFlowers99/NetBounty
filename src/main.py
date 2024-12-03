from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import re

def scan_network(network):
  arp = ARP(pdst=network) # Create ARP Request by setting the ARP function's package destination parameter `pdst` to the `network` argument.
  ether = Ether(dst="ff:ff:ff:ff:ff:ff") # Creates ethernet broadcast frame with all 6 octets set to 255 (ff) as to broadcast across the entire network.
  packet = ether / arp # Scapy uses operator overloading here to stack protocol layers, this is not division. 

  result = srp(packet, timeout = 2, verbose = False)[0] # Send packet & capture response. Scapy's srp() function is used for 2 layer packets, like ethernet here.

  devices = []
  for sent, recieved in result:
    devices.append({"IP": recieved.psrc, "MAC": recieved.hwsrc}) # The ARP response packet contains the `.psrc` (protocol source address) and 
                                                                 # `.hwsrc` (hardware source address) fields that we are appending to the devices array.
  
  return devices # Returns discovered devices w/ associated IP and MAC addrs.

def scan_ports(ip, ports):
  open_ports = []
  for port in ports:
    packet = IP(dst = ip) / TCP(dport = port, flags="S") # Creates TCP SYN data packet // Sets the IP function's destination address parameter `dst` to the `ip`
                                                         # argument and sets the TCP function's destination port parameter `dport` to the current `port` index.
                                                         # TCP's flags parameter is set to "S" for SYN.

    response = sr1(packet, timeout = 1, verbose = False) # Send packet and capture response. Scapy's sr1() function is used for 3 layer packets, like TCP/IP here.
                                                        # sr1() only captures a single return packet.

    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == "SA": # If the reponse contains a SYN-ACK flag then append port to `open_ports`.
      open_ports.append(port)
  
  return open_ports # Returns open ports.

def display_opening_msg():
    print( # What good is an app if it doesnt look cool when it's fired up?
  r"""
  _  _     _   ___               _        
 | \| |___| |_| _ ) ___ _  _ _ _| |_ _  _ 
 | .` / -_)  _| _ \/ _ \ || | ' \  _| || |
 |_|\_\___|\__|___/\___/\_,_|_||_\__|\_, |
                                     |__/ 
 Network Reconnaissance and Vulnerability Scanner
 by Caleb Keene

 ---

 Prof. Chinmoy Modak
 CSC-211-NW1
 Final Project

 ---
 
  """
  )

def main():
  display_opening_msg()

  # Define regex for checking IPv4 CIDR notation.
  cidr_regex = r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])" \
                 r"/(3[0-2]|[1-2]?[0-9])$"
  
  # Input validation.
  valid_input = False
  while (not valid_input): 
    user_input = input("Please enter IP to be scanned in IPv4 CIDR notation: ")
    if (re.match(cidr_regex, user_input)):
      valid_input = True
    else:
      print("Invalid Format! e.g >> (192.168.0.1/24)\n")

  # Scan network and output IP and MAC addrs.
  print(f"\nScanning {user_input}...")
  network = user_input
  devices = scan_network(network)
  for device in devices:
    print(f"IP: {device['IP']}, MAC: {device["MAC"]}")


if __name__ == "__main__":
  main()