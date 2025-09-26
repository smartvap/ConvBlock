#####################################
# IPTABLES Blocking Scripts v240317 #
#####################################

#!/bin/bash

##################################
# Policies for docker containers #
##################################

iptables -t raw -I PREROUTING -p tcp -s 194.114.0.0/24 -j ACCEPT # Standalone docker policies
iptables -t raw -I PREROUTING -p tcp -s 172.17.0.0/16 -j ACCEPT # Standalone docker policies

############################
# General Blocking Scripts #
############################

iptables -t raw -A PREROUTING -p tcp -m multiport --dports 22,179,1080,1180,1181,1183,2380,8080,10250,10256,10257,10259 -j DROP
