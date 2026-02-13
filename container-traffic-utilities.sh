########################################
# Container Traffic Utilities v260211  #
# Traffic Capture, Anaylze             #
########################################

#!/bin/bash

# [Note] Working principles: Analyze Host Exposures → Capture Packets → Generate iptables blocking execution plan
# [Improvement]

########################################
# Bugs, Defects and Other Problems     #
########################################

#########################################
# Environment variable setting area     #
#########################################

# Make sure the alias is available in this shell script
# Sometimes, some key commands need to be provided using aliases
# [Fixed] Sometimes the alias were defined in /etc/profile
shopt -s expand_aliases

#
# The configuration of environment variables and aliases takes effect immediately in the current shell environment.
#
if [ -f /etc/profile ]; then
   source /etc/profile
fi

if [ -f /etc/bashrc ]; then
   source /etc/bashrc
fi

if [ -f ~/.bash_profile ]; then
   source ~/.bash_profile
fi

if [ -f ~/.bashrc ]; then
   source ~/.bashrc
fi

if [ -f ~/.profile ]; then
   source ~/.profile
fi

