from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import nmap
from tabulate import tabulate
import re, time, threading, json
import xml.etree.ElementTree as ET

# Imports for troubleshooting below:
# from scapy.all import conf
# from scapy.arch.windows import *



def scan_network(network):
  arp = ARP(pdst=network) # Create ARP Request by setting the ARP function's package destination parameter `pdst` to the `network` argument.
  ether = Ether(dst="ff:ff:ff:ff:ff:ff") # Creates ethernet broadcast frame with all 6 octets set to 255 (ff) as to broadcast across the entire network.
  packet = ether / arp # Scapy uses operator overloading here to stack protocol layers, this is not division. 

  result = srp(packet, timeout = 3, verbose = False)[0] # Send packet & capture response. Scapy's srp() function is used for 2 layer packets, like ethernet here.

  devices = []
  for sent, recieved in result:
    devices.append({"IP": recieved.psrc, "MAC": recieved.hwsrc}) # The ARP response packet contains the `.psrc` (protocol source address) and 
                                                                 # `.hwsrc` (hardware source address) fields that we are appending to the devices array.

  return devices # Returns discovered devices w/ associated IP and MAC addrs.



def scan_ports(ips, ports):
  open_ports = {}
  for ip in ips:
    for port in ports:
      packet = IP(dst = ip) / TCP(dport = port, flags="S") # Creates TCP SYN data packet // Sets the IP function's destination address parameter `dst` to the `ip`
                                                          # argument and sets the TCP function's destination port parameter `dport` to the current `port` index.
                                                          # TCP's flags parameter is set to "S" for SYN.

      response = sr1(packet, timeout = 1, verbose = False) # Send packet and capture response. Scapy's sr1() function is used for 3 layer packets, like TCP/IP here.
                                                          # sr1() only captures a single return packet.

      if response and response.haslayer(TCP) and response.getlayer(TCP).flags == "SA": # If the reponse contains a SYN-ACK flag then append port to `open_ports`.
        open_ports.setdefault(ip, []).append(port)
  
  return open_ports # Returns IP addrs with associated open ports.



def identify_services_with_nmap(alive_ports):
    nm = nmap.PortScanner() # Creates Nmap PortScanner object
    results = {}
    
    for target_ip, ports in alive_ports.items():
        ports_str = ','.join(map(str, ports)) # Join ports list into a comma-separated string again.

        # New progress indicator thread
        stop_event = threading.Event()
        progress_thread = threading.Thread(target=progress_indicator, args=(stop_event, f"Identifying services at {target_ip} running on port(s): {ports_str}")) 
        progress_thread.start()
        
        # Perform the service scan with -Pn. Since we're only scanning alive hosts we can comfortably skip the host discovery phase.
        nm.scan(target_ip, ports_str, arguments='-sV -Pn')
        
        # stop progress indicator thread
        stop_event.set()
        progress_thread.join()
        print(" Done!")

        # Process and display results using raw XML parsing
        raw_xml = nm.get_nmap_last_output()  # Get the raw XML output
        root = ET.fromstring(raw_xml)  # Parse the XML

        for host in root.findall("host"):
            for port in host.find("ports").findall("port"):
                port_id = port.attrib['portid']
                service = port.find("service")
                name = service.attrib.get('name', 'Unknown')
                product = service.attrib.get('product', 'Unknown')
                version = service.attrib.get('version', 'Unknown')
                extra_info = service.attrib.get('extrainfo', '')

                results.setdefault(target_ip, []).append({
                  "port": int(port_id),
                  "service": name,
                  "product": product,
                  "version": version,
                  "extra_info": extra_info
                })
    return results



def display_opening_msg():
    print( # What good is an app if it doesnt look cool when it's fired up?
  r"""
  _  _     _   ___               _        
 | \| |___| |_| _ ) ___ _  _ _ _| |_ _  _ 
 | .` / -_)  _| _ \/ _ \ || | ' \  _| || |
 |_|\_\___|\__|___/\___/\_,_|_||_\__|\_, |
                                     |__/ 
 Simple Network Reconnaissance and Vulnerability Scanner
 by Caleb Keene

 ---

 Prof. Chinmoy Modak
 CSC-211-NW1
 Final Project

 ---
 
  """
  )



def progress_indicator(stop_event, what_is_happing): # Scanning network, ports, identifying services, etc.

  print(f"\n{what_is_happing} ", end = "")

  while not stop_event.is_set(): # while scan is still running...
    for _ in range(3):
      if stop_event.is_set():
        break
      print(". ", end = "", flush = True) # Print an ellipses every half second.
      time.sleep(0.5)
    if not stop_event.is_set():
      print("\b\b\b\b\b     \b\b\b\b\b\b", end="", flush=True) # Uses backspace character to erase ellipses and start over if still running.



def take_ip_range_input():
  # Define regex for checking IPv4 CIDR notation.
  cidr_regex = r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\." \
                 r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])" \
                 r"/(3[0-2]|[1-2]?[0-9])$"
  
  # Input validation.
  valid_input = False
  while (not valid_input): 
    try:
      user_input = input("Enter IP range to be scanned in IPv4 CIDR notation: ")
    except KeyboardInterrupt: # Gracefully exit program on Ctrl+C.
      print("Exiting...")
      exit()
    if (re.match(cidr_regex, user_input)): # Checks to see if the user's input matches the CIDR regular expression.
      valid_input = True
    else:
      print("Invalid Format! e.g >> (10.0.0.0/8)\n")

  return user_input



def take_port_range_input():
    # Define regex for numbers between 0 and 99999 separated by commas.
    port_regex = r"^(?:0|[1-9]\d{0,4})(?:,(?:0|[1-9]\d{0,4}))*$"
    
    valid_input = False
    while (not valid_input): 
      try:
        user_input = input("Enter ports to be scanned as comma-separated values: ")
      except KeyboardInterrupt: # Gracefully exit program on Ctrl+C.
        print("Exiting...")
        exit()
      if not re.fullmatch(port_regex, user_input): # Checks to see if the user's input matches the port number regular expression.
        print("Invalid Format! e.g. >> (22,80,443,3306)\n")
        continue
      else:
        ports = list(map(int, user_input.split(','))) # Converts to integers and checks range.
        if all(0 <= port <= 65535 for port in ports): # Makes sure ports specified are in bounds.
            return ports
        print("Err: Port numbers must be between 0-65535.\n") 
      



def main():

  # print(conf.iface) # While uncommented, displays network interface being used by scapy.
  # print(json.dumps(get_windows_if_list(), indent = 4)) displays all network interfaces (whilst ran on Windows).

  network = take_ip_range_input()
  ports = take_port_range_input()
  ips = []

  stop_event = threading.Event()  # Event to signal the progress_indicator thread to stop.
  progress_thread = threading.Thread(target=progress_indicator, args=(stop_event, f"Scanning network {network}")) # Defines progress_indicator as a thread with network parameter.
  
  try:
    progress_thread.start() # Starts progress_indicator thread.
    devices = scan_network(network) # Begins scanning network.
    ips = [device['IP'] for device in devices]
    table_data = [(device[('IP')], device[('MAC')]) for device in devices]
    headers = ["IP Address", "MAC Address"]
  except KeyboardInterrupt:
    print("Exiting...")
    exit()
  finally:
    stop_event.set() # Stop progress_indicator thread!
    progress_thread.join()  # Wait for the thread to finish.
    print(" Done!")

  if not devices:
    print("\nNo devices found on the network.\n")
    main() # Start over from the beginning.
  else:
    # Prints results nicely.
    print("\nDevices discovered:")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Starting progress indicator thread again for port scan.
    stop_event = threading.Event()
    progress_thread = threading.Thread(target=progress_indicator, args=(stop_event, f"Scanning ports {ports}"))
    progress_thread.start()

    alive_ports = scan_ports(ips, ports)

    stop_event.set()
    progress_thread.join()
    print(" Done!")

    print(f"\nDevices with open ports:\n{tabulate(alive_ports, headers = "keys")}\n") # Display alive ports.
    print(json.dumps(identify_services_with_nmap(alive_ports), indent = 3)) # Display services information



if __name__ == "__main__":
  display_opening_msg()
  main()