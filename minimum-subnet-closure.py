import sys
import ipaddress
from typing import List, Union, Optional

def find_minimum_subnet_closure(ip_list: List[str]) -> Optional[str]:
   """
   Find the minimum closure of a set of IPv4 or IPv6 addresses (the smallest subnet that accommodates this set of addresses)
   
   Parameters:
      Ip_st: IP address list, supports CIDR notation (such as "192.168.1.1/32") or pure IP addresses (such as "192.168.1.1")
   
   Return:
      CIDR representation of the smallest subnet, returns None if there is no IP address
   """
   if not ip_list:
      return None
   
   # Remove duplicates and resolve all IP addresses
   unique_ips = []
   seen = set()
   
   for ip_str in ip_list:
      if ip_str in seen:
         continue
      seen.add(ip_str)
      
      # Attempt to resolve to IP address
      try:
         # If it contains "/", divide it first
         if '/' in ip_str:
               ip_str = ip_str.split('/')[0]
         ip = ipaddress.ip_address(ip_str)
         unique_ips.append(ip)
      except ValueError as e:
         raise ValueError(f"Invalid IP address format: {ip_str}") from e
   
   if not unique_ips:
      return None
   
   # Check if all IPs are of the same type (IPv4 or IPv6)
   first_ip = unique_ips[0]
   for ip in unique_ips[1:]:
      if ip.version != first_ip.version:
         raise ValueError("Cannot mix IPv4 and IPv6 addresses")
   
   # If there is only one IP, directly return/32 (IPv4) or/128 (IPv6)
   if len(unique_ips) == 1:
      if first_ip.version == 4:
         return f"{first_ip}/32"
      else:
         return f"{first_ip}/128"
   
   # Convert to integers for comparison
   ip_ints = [int(ip) for ip in unique_ips]
   min_ip = min(ip_ints)
   max_ip = max(ip_ints)
   
   # Find a common prefix length
   xor_result = min_ip ^ max_ip
   
   if xor_result == 0:
      # All IPs are the same
      common_prefix_len = 32 if first_ip.version == 4 else 128
   else:
      # Calculate the number of leading zeros
      # For IPv4, the maximum number of bits is 32; IPv6 is 128
      max_bits = 32 if first_ip.version == 4 else 128
      
      # Find the position of the first different position
      # We need to calculate the position of the highest bit 1 in the binary representation of xor_result
      import math
      if xor_result == 0:
         first_different_bit = max_bits
      else:
         first_different_bit = max_bits - xor_result.bit_length()
      
      common_prefix_len = first_different_bit
   
   # Building the smallest subnet
   if first_ip.version == 4:
      # For IPv4
      network_address = ipaddress.IPv4Address(min_ip)
      network = ipaddress.IPv4Network(f"{network_address}/{common_prefix_len}", strict=False)
      
      # Check if this network really contains all IP addresses
      while common_prefix_len > 0:
         network = ipaddress.IPv4Network(f"{network_address}/{common_prefix_len}", strict=False)
         if all(ip in network for ip in unique_ips):
            break
         common_prefix_len -= 1
         if common_prefix_len <= 0:
            # If no suitable subnet is found, return the default 0.0.0.0/0
            return "0.0.0.0/0"
      
   else:
      # For IPv6
      network_address = ipaddress.IPv6Address(min_ip)
      network = ipaddress.IPv6Network(f"{network_address}/{common_prefix_len}", strict=False)
      
      # Check if this network really contains all IP addresses
      while common_prefix_len > 0:
         network = ipaddress.IPv6Network(f"{network_address}/{common_prefix_len}", strict=False)
         if all(ip in network for ip in unique_ips):
            break
         common_prefix_len -= 1
         if common_prefix_len <= 0:
            # If no suitable subnet is found, return the default::/0
            return "::/0"
   
   return str(network)


def find_minimum_subnet_closure_optimized(ip_list: List[str]) -> Optional[str]:
   """
   Optimized version, utilizing the built-in functionality of the ipaddress module
   """
   if not ip_list:
      return None
   
   # Remove duplicates and resolve all IP addresses
   networks = []
   seen = set()
   
   for ip_str in ip_list:
      if ip_str in seen:
         continue
      seen.add(ip_str)
      
      # Resolve to IP network
      try:
         if '/' in ip_str:
            net = ipaddress.ip_network(ip_str, strict=False)
         else:
            # If it is a pure IP, convert it to/32 or/128
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
               net = ipaddress.ip_network(f"{ip}/32", strict=False)
            else:
               net = ipaddress.ip_network(f"{ip}/128", strict=False)
         networks.append(net)
      except ValueError as e:
         raise ValueError(f"Invalid IP address format: {ip_str}") from e
   
   if not networks:
      return None
   
   # Check if all networks are of the same type
   first_version = networks[0].version
   for net in networks[1:]:
      if net.version != first_version:
         raise ValueError("Cannot mix IPv4 and IPv6 addresses")
   
   # If there is only one network, return directly
   if len(networks) == 1:
      return str(networks[0])
   
   # Extract all IP addresses
   all_ips = []
   for net in networks:
      if net.num_addresses == 1:
         all_ips.append(net.network_address)
      else:
         # For non/32 or non/128 networks, we need to include all addresses
         # But in reality, for the minimum closure, we only need to consider the boundary
         all_ips.append(net.network_address)
         all_ips.append(net.broadcast_address if first_version == 4 else net[-1])
   
   # Find the minimum and maximum IP addresses
   ip_ints = [int(ip) for ip in all_ips]
   min_ip = min(ip_ints)
   max_ip = max(ip_ints)
   
   # Calculate the minimum inclusion network
   if first_version == 4:
      # IPv4
      # Calculate how many prefixes are needed
      diff = max_ip - min_ip
      if diff == 0:
         prefixlen = 32
      else:
         # Find the required number of digits for coverage
         import math
         bits_needed = 32 - (diff.bit_length() - 1)
         
         # Ensure that the prefix length is valid
         prefixlen = max(0, bits_needed)
         
         # Adjust network address
         network_addr = ipaddress.IPv4Address(min_ip)
         
         # It may be necessary to adjust the network address to correctly include all addresses
         for pl in range(prefixlen, -1, -1):
               net = ipaddress.IPv4Network(f"{network_addr}/{pl}", strict=False)
               if all(ip in net for ip in all_ips):
                  return str(net)
      
      return f"{ipaddress.IPv4Address(min_ip)}/{prefixlen}"
   else:
      # IPv6
      diff = max_ip - min_ip
      if diff == 0:
         prefixlen = 128
      else:
         import math
         bits_needed = 128 - (diff.bit_length() - 1)
         prefixlen = max(0, bits_needed)
         
         network_addr = ipaddress.IPv6Address(min_ip)
         
         for pl in range(prefixlen, -1, -1):
               net = ipaddress.IPv6Network(f"{network_addr}/{pl}", strict=False)
               if all(ip in net for ip in all_ips):
                  return str(net)
      
      return f"{ipaddress.IPv6Address(min_ip)}/{prefixlen}"


if __name__ == "__main__":

   if len(sys.argv) < 2:
      print("Usage: python3 minimum-subnet-closure.py <IP Address 1> <IP Address 2> ...")
      print("Example: python3 minimum-subnet-closure.py 192.168.1.1 192.168.1.2 192.168.1.3")
      print("Example: python3 minimum-subnet-closure.py 169.169.0.100/32 169.169.255.255/32")
      print("Example: python3 minimum-subnet-closure.py 2001:db8::1 2001:db8::2")

   # Get command-line parameters (skip script name)
   ip_list = sys.argv[1:]
   
   try:
      result = find_minimum_subnet_closure_optimized(ip_list)
      print(f"{result}")
               
   except Exception as e:
      print(f"Error: {e}")
