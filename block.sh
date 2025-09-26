#####################################
# IPTABLES Blocking Scripts v240317 #
#####################################

#!/bin/bash

##################################
# Policies for K8s Nodes         #
##################################

iptables -t raw -I PREROUTING -p tcp -m iprange --src-range 192.168.80.11-192.168.80.15 -j ACCEPT

##################################
# Policies for docker containers #
##################################

iptables -t raw -I PREROUTING -p tcp -s 194.114.0.0/24 -j ACCEPT # Standalone docker policies
iptables -t raw -I PREROUTING -p tcp -s 172.17.0.0/16 -j ACCEPT # Standalone docker policies

############################
# General Blocking Scripts #
############################

iptables -t raw -A PREROUTING -p tcp -s 192.168.80.1 --dport 22 -j ACCEPT # 1045/sshd
iptables -t raw -A PREROUTING -p tcp -s 196.166.112.79 --dport 1183 -j ACCEPT # 1168/etcd
iptables -t raw -A PREROUTING -p tcp -s 192.168.80.1 --dport 8080 -j ACCEPT # 2129/docker-proxy
iptables -t raw -A PREROUTING -p tcp -m multiport --dports 22,179,1080,1180-1181,1183,2380,8080,10250,10256-10257,10259,12300-12305 -j DROP
