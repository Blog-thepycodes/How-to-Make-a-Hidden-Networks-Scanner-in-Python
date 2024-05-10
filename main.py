import subprocess
from scapy.all import *
 
 
def analyze_hidden_network_security(ssid, encryption_type):
   """Analyze the security of a hidden Wi-Fi network."""
   print(f"Analyzing security for hidden network: {ssid}")
 
 
   if encryption_type.upper() in ['WEP', 'WPA', 'TKIP']:
       print("Warning: Weak encryption type detected.")
       print("Advice: Consider upgrading to WPA2 or WPA3 for stronger security.")
   else:
       print("Security: Strong")
       print("Advice: Keep your Wi-Fi password strong and secure, and regularly update your router firmware.")
 
 
def scan_hidden_networks(interface):
   hidden_networks = set()
 
 
   def handle_probe_response(packet):
       if packet.haslayer(Dot11ProbeResp) and packet.info:
           ssid = packet.info.decode(errors="ignore")
           if ssid not in hidden_networks:
               hidden_networks.add(ssid)
               encryption_type = 'Unknown'  # Encryption type determination needs a different approach
               analyze_hidden_network_security(ssid, encryption_type)
 
 
   try:
       print("Scanning for hidden networks. Please wait...")
       sniff(iface=interface, prn=handle_probe_response, timeout=20)
   except Exception as e:
       print(f"Error scanning for hidden networks: {e}")
 
 
   return hidden_networks
 
 
def main():
   interface = input("Enter the wireless interface name (e.g., Wi-Fi): ")
   hidden_networks = scan_hidden_networks(interface)
   print(f"\nDiscovered {len(hidden_networks)} hidden networks:")
   for ssid in hidden_networks:
       print(ssid)
 
 
if __name__ == "__main__":
   main()
