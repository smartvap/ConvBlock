#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# [Note] The minimum supported version of Python required to run the current script is 3.7.0.
# The compilation and installation method is as follows:
#  
#

import re
import ipaddress
import argparse
import sys
import socket
import random
import json
from urllib.parse import urlparse
from netaddr import IPAddress, cidr_merge
from ipaddress import ip_network

def is_ip_in_pools(ip_str, *subnet_pools):
   """
   Determine whether an IP address belongs to any specified subnet address pool.

   Parameters:
      ip_str (str): The IP address to be checked, such as "192.168.122.45" or "2001:db8::1"
      *subnet_pools (str): Variable number of subnet parameters, each parameter is a subnet string.

   Return:
      bool: If the IP address belongs to any subnet in the address pool, return True; Otherwise, return False.
   """
   if not subnet_pools:
      raise ValueError("At least one subnet address pool needs to be provided for judgment.")

   try:
      # Convert the input string into an IP address object
      ip_obj = ipaddress.ip_address(ip_str)
   except ValueError:
      raise ValueError(f"'{ip_str}' is not a valid IP address format.")

   # Traverse all incoming subnets
   for subnet in subnet_pools:
      try:
         # Create subnet object, strict=False allows non strict network addresses
         network = ipaddress.ip_network(subnet, strict=False)
         # Check if the IP belongs to the current subnet
         if ip_obj in network:
               return True
      except ValueError:
         # If a subnet format is invalid, skip and continue checking for the next one
         print(f"Warnings: Subnet '{subnet}' format is invalid, skipped.", file=sys.stderr)
         continue

   # If all subnets do not match after traversal, return False.
   return False

def is_subnet(subnet_a, subnet_b):
   """
   Determine whether subnet subnet-a belongs to subnet subnet-b.

   Paramters:
      subnet_a (str): The subnet to be determined, in the format of '192.168.0.10/25', not strict
      subnet_b (str): Target parent network, format such as' 192.168.0.7/24', not strict
   
   Return:
      bool: If subnet-a is a subnet of subnet-b, return True; otherwise, return False.
   """
   try:
      net_a = ip_network(subnet_a, strict=False)
      net_b = ip_network(subnet_b, strict=False)
      return net_a.subnet_of(net_b)
   except ValueError as e:
      print(f"Error: Invalid subnet format - {e}")
      return False

def extract_ip_from_url(*url_list):
   """
   Extract IP address from URL (supports IPv4 and IPv6)
   Supports multiple URLs as input
   """
   results = []
   
   for url in url_list:
      try:
         parsed = urlparse(url)

         hostname = parsed.hostname

         if hostname is None:
            continue

         ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
         ipv6_pattern = r'^\[?([a-fA-F0-9:]+)\]?$'
         
         if re.match(ipv4_pattern, hostname):
            results.append(hostname)
            continue
         
         ipv6_match = re.match(ipv6_pattern, hostname)
         if ipv6_match:
            results.append(ipv6_match.group(1))
            continue
         
      except Exception as e:
         print(f"Error parsing URL '{url}': {e}")
   
   return results

def validate_ip(ip):
   """Verify IP address format"""
   try:
      IPAddress(ip)
      return True
   except:
      return False

def ip_to_ranges(*ip_list):

   results = []
   
   # Filter invalid IPs and remove duplicates
   valid_ips = []
   for ip in set(ip_list):
      if validate_ip(ip):
         valid_ips.append(IPAddress(ip))
      else:
         print(f"Warning: Skipping invalid IP addresses: {ip}")
   
   if not valid_ips:
      return results
   
   # Sort
   valid_ips.sort()
   
   start_ip = valid_ips[0]
   end_ip = valid_ips[0]
   
   for i in range(1, len(valid_ips)):
      current_ip = valid_ips[i]
      previous_ip = valid_ips[i-1]
      
      # Check if it is continuous (current IP=previous IP+1)
      if int(current_ip) == int(previous_ip) + 1:
         end_ip = current_ip
      else:
         # Save current range
         if start_ip == end_ip:
            results.append(str(start_ip))
         else:
            results.append(f"{start_ip}-{end_ip}")
         
         # Start a new range
         start_ip = current_ip
         end_ip = current_ip
   
   # Handle the final range
   if start_ip == end_ip:
      results.append(str(start_ip))
   else:
      results.append(f"{start_ip}-{end_ip}")

   return results

def get_ip_family(ip):
   try:
      ipaddress.IPv4Address(ip)
      return "IPv4"
   except ipaddress.AddressValueError:
      try:
         ipaddress.IPv4Network(ip, strict=False)
         return "IPv4"
      except ipaddress.AddressValueError:
         try:
            ipaddress.IPv6Address(ip)
            return "IPv6"
         except ipaddress.AddressValueError:
            try:
               ipaddress.IPv6Network(ip, strict=False)
               return "IPv6"
            except ipaddress.AddressValueError:
               return "Invalid"

def generate_random_10_subnet():
   """
   Generate a random 10._._._/30 subnet addresses
   
   return:
      str: 10._._._/30 style subnet address
   """
   second_octet = random.randint(0, 255)
   third_octet = random.randint(0, 255)
   fourth_octet = random.randint(0, 255) & 0xFC  # Ensure alignment is/30 (with the last digit being 0)
   
   subnet_addr = f"10.{second_octet}.{third_octet}.{fourth_octet}/30"
   return subnet_addr

def generate_random_10_subnet_with_ips():
   """
   Generate random 10. _ _. _/30 subnets, and return subnet information and available IP addresses
   
   return:
      dict: Dictionary containing subnet information and available IP addresses
   """
   subnet_str = generate_random_10_subnet()
   network = ipaddress.IPv4Network(subnet_str, strict=False)
   
   # Get all available host addresses (excluding network addresses and broadcast addresses)
   usable_ips = [str(ip) for ip in network.hosts()]
    
   json_object = {
      "subnet": subnet_str,
      "network_address": str(network.network_address),
      "broadcast_address": str(network.broadcast_address),
      "usable_ips": usable_ips,
      "total_addresses": network.num_addresses,
      "usable_count": len(usable_ips)
   }

   json_string = json.dumps(json_object, indent=4)

   return json_string

def extract_usable_ips(cidr_input):
   try:
      network = ipaddress.ip_network(cidr_input, strict=False)
      usable_ips = [str(ip) for ip in network.hosts()]
      return usable_ips
   except ValueError as e:
      print(f"Error: Invalid CIDR Format - {e}")
      return []
   except Exception as e:
      print(f"Error: {e}")
      return []

def main():
   parser = argparse.ArgumentParser(
      description="Network Tool Set - IP Address and Subnet Management Tool",
      epilog="""
Examples:
   python3 network-utilities.py --check-ip-in-pools 192.168.122.45 192.168.122.0/25 192.168.122.128/25
   python3 network-utilities.py --is-subnet 192.168.0.10/25 192.168.0.7/24
   python3 network-utilities.py --extract-ip-from-url https://192.168.1.1:8080/start
   python3 network-utilities.py --ip-to-ranges 192.168.0.1 192.168.0.2 192.168.0.3
   python3 network-utilities.py --get-ip-family ::1
   python3 network-utilities.py --generate-random-10-subnet-with-ips
   python3 network-utilities.py --extract-usable-ips 192.168.0.0/30
""",
      formatter_class=argparse.RawDescriptionHelpFormatter
   )
   
   parser.add_argument('--check-ip-in-pools', nargs='+', 
      metavar=('IP', 'SUBNET'), 
      help='Check if the IP address belongs to the specified subnet address pool')
   
   parser.add_argument('--is-subnet', nargs='+', 
      metavar=('SUBNET_A', 'SUBNET_B'), 
      help='Determine whether subnet subnet-a belongs to subnet subnet-b')

   parser.add_argument('--extract-ip-from-url', nargs='+',
      metavar=('URL'), 
      help='Extract IP from URL')

   parser.add_argument('--ip-to-ranges', nargs='+',
      metavar=('IP'),
      help='Split the IP address list into address ranges')

   parser.add_argument('--get-ip-family', nargs='+',
      metavar=('IP'),
      help='Get the IP family')
   
   parser.add_argument('--generate-random-10-subnet-with-ips',
      action='store_true',
      help='Get a random 10._._._/30 subnet address')
   
   parser.add_argument('--extract-usable-ips', nargs='+',
      metavar=('CIDR_INPUT'),
      help='Extrace usable IPs from CIDR')
   
   args = parser.parse_args()
   
   if args.check_ip_in_pools:
      if len(args.check_ip_in_pools) < 2:
         print("Error: IP address and at least one subnet are required", file=sys.stderr)
         return 1
      
      ip_address = args.check_ip_in_pools[0]
      subnets = args.check_ip_in_pools[1:]
      
      try:
         result = is_ip_in_pools(ip_address, *subnets)
         print(f"{result}")
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.is_subnet:
      if len(args.is_subnet) < 2:
         print("Error, You must provide 2 subnets", file=sys.stderr)
         return 1
      
      subnet_a = args.is_subnet[0]
      subnet_b = args.is_subnet[1]

      try:
         result = is_subnet(subnet_a, subnet_b)
         print(f"{result}")
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.extract_ip_from_url:
      if len(args.extract_ip_from_url) < 1:
         print("Error: At least one URL is required", file=sys.stderr)
         return 1
      
      url_list = args.extract_ip_from_url[0:]

      try:
         result = extract_ip_from_url(*url_list)
         print('\n'.join(result))
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.ip_to_ranges:
      if len(args.ip_to_ranges) < 1:
         print("Error: At least one IP address is required", file=sys.stderr)
         return 1
      
      ip_list = args.ip_to_ranges[0:]

      try:
         result = ip_to_ranges(*ip_list)
         print('\n'.join(result))
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.get_ip_family:
      if len(args.get_ip_family) < 1:
         print("Error: At least one IP address is required", file=sys.stderr)
         return 1
      
      ip_address = args.get_ip_family[0]

      try:
         result = get_ip_family(ip_address)
         print(result)
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.generate_random_10_subnet_with_ips:
      try:
         result = generate_random_10_subnet_with_ips()
         print(result)
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   elif args.extract_usable_ips:
      if len(args.extract_usable_ips) < 1:
         print("Error: At least one CIDR is required", file=sys.stderr)
         return 1
      
      cidr = args.extract_usable_ips[0]

      try:
         result = extract_usable_ips(cidr)
         print('\n'.join(result))
         return 0
      except ValueError as e:
         print(f"Error: {e}", file=sys.stderr)
         return 1
   
   parser.print_help()
   return 0

if __name__ == "__main__":
   sys.exit(main())