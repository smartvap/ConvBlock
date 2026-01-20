####################################
# Compose Ports Access Controller  #
# v1.0                             #
####################################

#!/bin/bash

####################################
# Precautions                      #
####################################

# This script is used for security protection of the docker-compose ports. Please copy this delivery to the docker-compose project directory to ensure that it is in the same directory as docker-compose.yml

####################################
# Bugs, Defects and Other Problems #
####################################

####################################
# Environment variables            #
####################################

#
# [Note] Make sure the alias is available in this shell script
# Sometimes, some key commands need to be provided using aliases
# Sometimes, the alias were defined in /etc/profile
#
shopt -s expand_aliases

#
# [Note] The configuration of environment variables and aliases takes effect immediately in the current shell environment.
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

#
# [Note] Initialize the variables of working directory path and tunnel revoke scripts folder path
#
WORKING_DIRECTORY=$(dirname $(realpath $0))
if [ $? -ne 0 ]; then
   WORKING_DIRECTORY=$(pwd)
fi

#
# [Note] The subnets on Loopback Interface. The system service can listen at address 127.0.0.0/8, so that the service is only available locally and will not be exposed to external networks, improving security. Use ip a show lo to get the subnets addresses. Not strict mode.
#
LOOPBACK_SUBNETS_IPV4=127.0.0.0/8
LOOPBACK_SUBNETS_IPV6=::1/128

#
# [Note] Known error messages that occur after executing the iptables command will be ignored.
#
IGNORED_ERROR_MESSAGES=(
   "does a matching rule exist in that chain"
   "iptables-legacy tables present"
)

IGNORED_ERROR_MESSAGES_STRING=$(echo "${IGNORED_ERROR_MESSAGES[@]}" | tr ' ' '|')

####################################
# Dependency components detection  #
####################################

#
# [Note] To facilitate iptables policy maintenance, the xt_comment module must be enabled.
#
if [ $(lsmod | grep xt_comment | wc -l) -eq 0 ]; then
   modprobe xt_comment
   if [ $(lsmod | grep xt_comment | wc -l) -eq 0 ]; then
      echo '[Warn] xt_comment module cannot be enabled.'
      exit 1
   fi
fi

if [ $(lsmod | grep xt_iprange | wc -l) -eq 0 ]; then
   modprobe xt_iprange
   if [ $(lsmod | grep xt_iprange | wc -l) -eq 0 ]; then
      echo '[Warn] xt_iprange module cannot be enabled.'
      exit 1
   fi
fi

if [ $(lsmod | grep xt_multiport | wc -l) -eq 0 ]; then
   modprobe xt_multiport
   if [ $(lsmod | grep xt_multiport | wc -l) -eq 0 ]; then
      echo '[Warn] xt_multiport module cannot be enabled.'
      exit 1
   fi
fi

if [ -z "$(which yq | head -1)" ]; then
   echo '[Warn] Please install yq 3.4.1 first.'
   exit -1
fi

#
# [Note] On the basis of the original grouping and merging function, add functions such as deduplication, sorting, and quantity limitation
# [Usage]
# echo '
#    192.168.0.1 8009
#    192.168.0.1 8005
#    192.168.0.2 7003
#    192.168.0.1 8001
#    192.168.0.1 8015
#    192.168.0.1 8010
#    192.168.0.1 8007
#    192.168.0.1 8004
#    192.168.0.1 8011
#    192.168.0.2 7002
#    192.168.0.1 8008
#    192.168.0.1 8004
#    192.168.0.1 8002
#    192.168.0.1 8006
#    192.168.0.1 8003
#    192.168.0.1 8014
#    192.168.0.1 8012
#    192.168.0.1 8013
#    192.168.0.2 7001
#    192.168.0.1 8016
#    192.168.0.1 8017
#    192.168.0.1 8018
# ' | group_by_1st_column
#
group_by_1st_column() {
   awk '
   {
      # De duplication: Each second column value corresponding to the first column is only recorded once
      if (!seen[$1","$2]++) {
         # Record values and mark the need for sorting
         value_count[$1]++
         values[$1][value_count[$1]] = $2
      }
   }
   END {
      # Traverse all groups
      for (key in values) {
         count = 0
         group_index = 1
         result = ""
         
         # Sort values numerically
         n = value_count[key]
         for (i = 1; i <= n; i++) {
            temp_arr[i] = values[key][i]
         }
         asort(temp_arr, sorted_values)
         
         # Build group output
         for (i = 1; i <= n; i++) {
            if (count++ > 0) result = result ","
            result = result sorted_values[i]
               
            if (count >= 15) {
               print key " " result
               result = ""
               count = 0
               group_index++
            }
         }
            
         if (count > 0) {
            print key " " result
         }
      }
   }'
}

#
# [Note] Convert subnet address to standard subnet address format.
# [Example] 192.168.0.2/24 → 192.168.0.0/24, 192.168.0.2/255.255.255.0 → 192.168.0.0/24
#
standardize_ip_address() {

   local ipAddr=$1
   echo $(python3 -c "import ipaddress; print(ipaddress.ip_network('$ipAddr', strict=False))")
}

#
# [Note] Batch convert subnet addresses to standard subnet addresses.
#
standardize_ip_addresses() {

   local ipAddrs=( ${*} )
   local result=()

   for ipAddr in ${ipAddrs[@]}; do
      ipAddr=$(python3 -c "import ipaddress; print(ipaddress.ip_network('$ipAddr', strict=False))")
      result=(${result[@]} $ipAddr)
   done

   echo "${result[@]}"
}

#
# [Note] This operation is in high dangerous
#
overwrite_shell_script_header() {

   local filePath=$1

   touch $filePath

   echo '#!/bin/bash' > $filePath
   echo >> $filePath
   echo '# [Note] The current script is automatically created by the program. Please review it strictly before executing it.' >> $filePath
   echo '# [Warn] If you confirm that it can be executed, please uncomment the following line.' >> $filePath
   echo 'exit -1' >> $filePath
   echo >> $filePath
}

#
# [Note] Obtain the docker-compose project name and the iptables comment
#
get_compose_project_name() {

   # According to the Docker Compose configuration specification, all Docker Compose projects should specify a private network name that is consistent with the project name.
   PROJECT_NAME=$(yq r -p p ${WORKING_DIRECTORY}/docker-compose.yml networks[*] | sed 's#networks.##g' | head -1)
   if [ -z "${PROJECT_NAME}" ]; then
      echo '[Warn] We suggest specifying the network bridge used by the current project in docker-compose.yml'
      
      # Normally, the project name is the directory name where docker-compose.yml is located
      PROJECT_NAME=$(basename ${WORKING_DIRECTORY})
   fi

   IPTABLES_COMMENT="${PROJECT_NAME} Access Control"
}

load_default_route_ip_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.default-route-addresses ] || [[ "${*}" =~ "--no-cache" ]]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-default-route-ip-addresses
   fi

   DEFAULT_ROUTE_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.default-route-addresses 2>/dev/null))
   DEFAULT_IPV4_ROUTE_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.default-ipv4-route-addresses 2>/dev/null))
   DEFAULT_IPV6_ROUTE_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.default-ipv6-route-addresses 2>/dev/null))
}

load_docker_subnet_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.docker-networks ] || [[ "${*}" =~ "--no-cache" ]]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-docker-subnet-addresses
   fi

   DOCKER_NETWORK_SUBNETS=($(cat ${WORKING_DIRECTORY}/.docker-networks 2>/dev/null))
   DOCKER_NETWORK_SUBNETS_IPV4=($(cat ${WORKING_DIRECTORY}/.docker-networks-ipv4 2>/dev/null))
   DOCKER_NETWORK_SUBNETS_IPV6=($(cat ${WORKING_DIRECTORY}/.docker-networks-ipv6 2>/dev/null))
}

#
# [Note] Allow interconnections between containers sharing the current docker-compose defined network, this is preventive strategy, when the host initiates a strong protection policy based on a wildcard address (such as denying any to any access), ensures that containers sharing the current compose network can access each other. Specifically, a trusted subnet or IP should include: the bridge used by docker-compose, the loopback network of the operating system, and the default routing IP address of the host.
#
allow_access_between_compose_containers() {

   local i=

   # Retrieve static docker-compose subnet data
   COMPOSE_CIDRS=($(yq r ${WORKING_DIRECTORY}/docker-compose.yml networks[*].ipam.config[*].ip_range))
   COMPOSE_IPV4_CIDRS=()
   COMPOSE_IPV6_CIDRS=()

   for i in ${CONTAINER_CIDRS[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family "$i")
      if [ "$ipFamily" == "IPv4" ]; then
         COMPOSE_IPV4_CIDRS=(${COMPOSE_IPV4_CIDRS[@]} $i)
      elif [ "$ipFamily" == "IPv6" ]; then
         COMPOSE_IPV6_CIDRS=(${COMPOSE_IPV6_CIDRS[@]} $i)
      fi
   done

   # Compulsory acquisition of default route IP addresses
   load_default_route_ip_addresses_from_file --no-cache

   # Compulsory acquisition of all docker bridge networks
   load_docker_subnet_addresses_from_file --no-cache

   # Merge into trusted CIDRs
   TRUST_IPV4_CIDRS=(${COMPOSE_IPV4_CIDRS[@]} ${DEFAULT_IPV4_ROUTE_ADDRESSES[@]} ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${LOOPBACK_SUBNETS_IPV4})

   TRUST_IPV6_CIDRS=(${COMPOSE_IPV6_CIDRS[@]} ${DEFAULT_IPV6_ROUTE_ADDRESSES[@]} ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${LOOPBACK_SUBNETS_IPV6})

   # Remove duplicates
   TRUST_IPV4_CIDRS=($(echo ${TRUST_IPV4_CIDRS[@]} | tr ' ' '\n' | sort -u))
   TRUST_IPV6_CIDRS=($(echo ${TRUST_IPV6_CIDRS[@]} | tr ' ' '\n' | sort -u))

   get_compose_project_name

   # [Note] Distinguish between trusted network policies and protective policies to avoid affecting trusted network policies during maintenance operations on protective policies
   local iptablesComment="${PROJECT_NAME} Trust Access Control"

   overwrite_shell_script_header ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   # Add and remove existing iptables scripts, otherwise ipset will be locked and cannot be deleted or rebuilt
   # echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "for i in \$(iptables -t raw -L PREROUTING -n --line-number | grep \"$iptablesComment\" | awk '{print \$1}' | sort -nr); do" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "   iptables -t raw -D PREROUTING \$i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "done" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   # echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "for i in \$(ip6tables -t raw -L PREROUTING -n --line-number | grep \"$iptablesComment\" | awk '{print \$1}' | sort -nr); do" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "   ip6tables -t raw -D PREROUTING \$i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "done" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "ipset destroy ${PROJECT_NAME}-trust-ipv4-subnets" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   # echo "ipset destroy ${PROJECT_NAME}-trust-ipv6-subnets" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "ipset create ${PROJECT_NAME}-trust-ipv4-subnets hash:net 2>/dev/null" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "ipset create ${PROJECT_NAME}-trust-ipv6-subnets hash:net family inet6 2>/dev/null" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   

   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   for i in ${TRUST_IPV4_CIDRS[@]}; do
      echo "ipset add ${PROJECT_NAME}-trust-ipv4-subnets $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   done

   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   for i in ${TRUST_IPV6_CIDRS[@]}; do
      echo "ipset add ${PROJECT_NAME}-trust-ipv6-subnets $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   done

   # Communications in TCP4/UDP4
   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "iptables -t raw -C PREROUTING -m set --match-set ${PROJECT_NAME}-trust-ipv4-subnets src -m set --match-set ${PROJECT_NAME}-trust-ipv4-subnets dst -m comment --comment \"$iptablesComment\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "iptables -t raw -I PREROUTING -m set --match-set ${PROJECT_NAME}-trust-ipv4-subnets src -m set --match-set ${PROJECT_NAME}-trust-ipv4-subnets dst -m comment --comment \"$iptablesComment\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   # Communications in TCP6/UDP6
   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "ip6tables -t raw -C PREROUTING -m set --match-set ${PROJECT_NAME}-trust-ipv6-subnets src -m set --match-set ${PROJECT_NAME}-trust-ipv6-subnets dst -m comment --comment \"$iptablesComment\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script
   echo "ip6tables -t raw -I PREROUTING -m set --match-set ${PROJECT_NAME}-trust-ipv6-subnets src -m set --match-set ${PROJECT_NAME}-trust-ipv6-subnets dst -m comment --comment \"$iptablesComment\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   sed -i '/^$/N;/^\n$/D' ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script

   echo "[Info] The preventive iptables allow rules have been saved in ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script"
}

#
# [Note] Get exposed hosts and ports from docker-compose.yml. Effective in non host network mode.
#
generate_port_mapping_tables() {

   local n=$(yq r ${WORKING_DIRECTORY}/docker-compose.yml services.[*].network_mode | grep -i host | wc -l)
   if [ $n -ne 0 ]; then
      echo '[Warn] There are host network mode services in the current docker-compose project, and the port exposures of these services are unknown.'
   fi

   load_default_route_ip_addresses_from_file --no-cache

   # Read CURRENT_IP variables from .env, this file is generated by network-utilities.sh
   if [ ! -f ${WORKING_DIRECTORY}/.env ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-current-ip-environment
   fi

   # CURRENT_IP variable is not a mandatory option, but we suggest setting this variable in the docker-compose project to ensure smaller port exposure surfaces
   if [ -f ${WORKING_DIRECTORY}/.env ]; then
      eval $(cat ${WORKING_DIRECTORY}/.env | sed 's# ##g')
   fi

   # Read port mappings in docker-compose.yml in the format of:
   # [<exposed ip>:]<exposed port>:<container port>[/<protocol>]
   # 8080:8080/tcp
   PORT_MAPPINGS=$(eval $(echo $(yq r ${WORKING_DIRECTORY}/docker-compose.yml services.[*].ports[*] | sed 's#^#echo #' | sed 's#$#;#g')))

   PORT_MAPPINGS_IPV4=($(echo ${PORT_MAPPINGS[@]} | tr ' ' '\n' | grep -vE '\[.*\]'))
   PORT_MAPPINGS_IPV6=($(echo ${PORT_MAPPINGS[@]} | tr ' ' '\n' | grep -E '\[.*\]'))

   # Standardize the format as <exposed ip>:<exposed port>:<container port>
   # By default, If the HostIP for listening is not specified, the default listening is on IPv4 wildcard address: 0.0.0.0, but not IPv6 address.
   PORT_MAPPINGS_IPV4=($(echo ${PORT_MAPPINGS_IPV4[@]} | tr ' ' '\n' | awk -F: '{
      # Save the original number of fields
      original_nf = NF
      
      # Process the last column
      if ($NF !~ /\//) {
         $NF = $NF "/tcp"
      }
      
      # Output based on the original number of fields
      if (original_nf == 3) {
         # Reconnect all fields with a colon
         result = $1
         for (i = 2; i <= NF; i++) {
               result = result ":" $i
         }
         print result
      } else if (original_nf == 2) {
         print "0.0.0.0:" $1 ":" $2
      }
   }'))

   # Complete the protocol for port mapping table
   PORT_MAPPINGS_IPV6=($(echo ${PORT_MAPPINGS_IPV6[@]} | tr ' ' '\n' | sed '/\//!s/$/\/tcp/'))

   # Convert to an exact mapping table
   EXPLICIT_PORT_MAPPINGS_IPV4=($(echo ${PORT_MAPPINGS_IPV4[@]} | tr ' ' '\n' | awk -F: -v ips="${DEFAULT_IPV4_ROUTE_ADDRESSES[*]}" '
      BEGIN {
         split(ips, ip_array, " ")
      }
      {
         if ($1 == "0.0.0.0") {
            for (i in ip_array) {
               print ip_array[i] ":" $2 ":" $3
            }
         } else {
            print $0
         }
      }
   '))

   echo ${EXPLICIT_PORT_MAPPINGS_IPV4[@]} | tr ' ' '\n' > ${WORKING_DIRECTORY}/.explicit-port-mappings-ipv4

   EXPLICIT_PORT_MAPPINGS_IPV6=($(echo ${PORT_MAPPINGS_IPV6[@]} | tr ' ' '\n' | awk -v ips="${DEFAULT_IPV6_ROUTE_ADDRESSES[*]}" '
      BEGIN {
         split(ips, ip_array, " ")
         ip_count = length(ip_array)
      }
      {
         original_line = $0
         if (original_line ~ /\[::\]/) {
            for (i = 1; i <= ip_count; i++) {
               line_copy = original_line
               gsub(/\[::\]/, "[" ip_array[i] "]", line_copy)
               print line_copy
            }
         } else {
            print original_line
         }
      }
   '))

   echo ${EXPLICIT_PORT_MAPPINGS_IPV6[@]} | tr ' ' '\n' > ${WORKING_DIRECTORY}/.explicit-port-mappings-ipv6

   echo "[Info] Explicit port mapping tables have been saved in ${WORKING_DIRECTORY}/.explicit-port-mappings-ipv4 and ${WORKING_DIRECTORY}/.explicit-port-mappings-ipv6"
}

#
# [Note] After implementing this policy, the remote peer in .legacy-clients will be allowed to access the exposed ports of current docker-compose containers.
#
generate_iptables_allow_rules() {

   local i=

   if [ ! -f ${WORKING_DIRECTORY}/.legacy-clients ] || [ $(cat .legacy-clients | wc -l) -eq 0 ]; then
      echo '[Warn] No authorized client IP has been configured yet.'
      return
   fi

   # 1. Scan the authorized client IP list and classify it according to IPv4/6.
   LEGACY_CLIENTS_IPV4=()
   LEGACY_CLIENTS_IPV6=()

   for i in $(cat ${WORKING_DIRECTORY}/.legacy-clients); do

      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family "$i")
      if [ "$ipFamily" == "IPv4" ]; then
         LEGACY_CLIENTS_IPV4=(${LEGACY_CLIENTS_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         LEGACY_CLIENTS_IPV6=(${LEGACY_CLIENTS_IPV6[@]} "$i")
      else
         echo "[Warn] .legacy-clients contains invalid IPv4/6 address $i."
      fi
   done

   if [ ${#LEGACY_CLIENTS_IPV4[@]} -ne 0 ]; then
      echo '[Info] The authorized client IPv4 addresses:'
      echo ${LEGACY_CLIENTS_IPV4[@]} | tr ' ' '\n' | sed 's#^#   #g'
   fi

   if [ ${#LEGACY_CLIENTS_IPV6[@]} -ne 0 ]; then
      echo '[Info] The authorized client IPv6 addresses:'
      echo ${LEGACY_CLIENTS_IPV6[@]} | tr ' ' '\n' | sed 's#^#   #g'
   fi

   # 2. Generate docker-compose port mapping tables
   generate_port_mapping_tables

   # 3. Obtain docker-compose project name and iptables comments
   get_compose_project_name

   # 4. Generate iptables strategies
   overwrite_shell_script_header ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

   # Add and remove existing iptables scripts, otherwise IPsec will be locked and cannot be deleted or rebuilt
   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "for i in \$(iptables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\" | awk '{print \$1}' | sort -nr); do" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "   iptables -t raw -D PREROUTING \$i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "done" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "for i in \$(ip6tables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\" | awk '{print \$1}' | sort -nr); do" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "   ip6tables -t raw -D PREROUTING \$i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "done" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

   if [ ${#EXPLICIT_PORT_MAPPINGS_IPV4[@]} -ne 0 ]; then
      
      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-legacy-clients-ipv4" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-exposed-tcp4" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-exposed-udp4" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-legacy-clients-ipv4 hash:net" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-exposed-tcp4 hash:ip,port" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-exposed-udp4 hash:ip,port" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      
      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in ${LEGACY_CLIENTS_IPV4[@]}; do
         echo "ipset add ${PROJECT_NAME}-legacy-clients-ipv4 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in $(echo ${EXPLICIT_PORT_MAPPINGS_IPV4[@]} | tr ' ' '\n' | grep '/tcp$' | awk -F: '{print $1",tcp:"$2}'); do
         echo "ipset add ${PROJECT_NAME}-exposed-tcp4 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in $(echo ${EXPLICIT_PORT_MAPPINGS_IPV4[@]} | tr ' ' '\n' | grep '/udp$' | awk -F: '{print $1",udp:"$2}'); do
         echo "ipset add ${PROJECT_NAME}-exposed-udp4 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "iptables -t raw -C PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv4 src -m set --match-set ${PROJECT_NAME}-exposed-tcp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "iptables -t raw -I PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv4 src -m set --match-set ${PROJECT_NAME}-exposed-tcp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "iptables -t raw -C PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv4 src -m set --match-set ${PROJECT_NAME}-exposed-udp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "iptables -t raw -I PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv4 src -m set --match-set ${PROJECT_NAME}-exposed-udp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   fi

   if [ ${#EXPLICIT_PORT_MAPPINGS_IPV6[@]} -ne 0 ]; then
      
      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-legacy-clients-ipv6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-exposed-tcp6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset destroy ${PROJECT_NAME}-exposed-udp6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-legacy-clients-ipv6 hash:net family inet6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-exposed-tcp6 hash:ip,port family inet6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ipset create ${PROJECT_NAME}-exposed-udp6 hash:ip,port family inet6" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      
      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in ${LEGACY_CLIENTS_IPV6[@]}; do
         echo "ipset add ${PROJECT_NAME}-legacy-clients-ipv6 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in $(echo ${EXPLICIT_PORT_MAPPINGS_IPV6[@]} | tr ' ' '\n' | grep '/tcp$' | sed 's#^\[\([^]]*\)\]:\([0-9]*\).*#\1,tcp:\2#g'); do
         echo "ipset add ${PROJECT_NAME}-exposed-tcp6 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      for i in $(echo ${EXPLICIT_PORT_MAPPINGS_IPV6[@]} | tr ' ' '\n' | grep '/udp$' | sed 's#^\[\([^]]*\)\]:\([0-9]*\).*#\1,udp:\2#g'); do
         echo "ipset add ${PROJECT_NAME}-exposed-udp6 $i" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      done

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ip6tables -t raw -C PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv6 src -m set --match-set ${PROJECT_NAME}-exposed-tcp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ip6tables -t raw -I PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv6 src -m set --match-set ${PROJECT_NAME}-exposed-tcp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ip6tables -t raw -C PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv6 src -m set --match-set ${PROJECT_NAME}-exposed-udp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
      echo "ip6tables -t raw -I PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-legacy-clients-ipv6 src -m set --match-set ${PROJECT_NAME}-exposed-udp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   fi

   # The query script
   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "iptables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\"" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script
   echo "ip6tables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\"" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

   # Convert multiple consecutive blank lines into one blank line
   sed -i '/^$/N;/^\n$/D' ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script

   echo "[Info] The iptables allow rules have been saved in ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script"
}

#
# [Note] Generate iptables blocking strategy scripts based on port exposure surface file. This function uses ipset to improve performance.
#
generate_iptables_reject_rules() {

   generate_port_mapping_tables

   get_compose_project_name

   overwrite_shell_script_header ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script

   if [ ${#EXPLICIT_PORT_MAPPINGS_IPV4[@]} -ne 0 ]; then

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "iptables -t raw -C PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-exposed-tcp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "iptables -t raw -A PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-exposed-tcp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "iptables -t raw -C PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-exposed-udp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "iptables -t raw -A PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-exposed-udp4 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
   fi

   if [ ${#EXPLICIT_PORT_MAPPINGS_IPV6[@]} -ne 0 ]; then

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "ip6tables -t raw -C PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-exposed-tcp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "ip6tables -t raw -A PREROUTING -p tcp -m set --match-set ${PROJECT_NAME}-exposed-tcp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script

      echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "ip6tables -t raw -C PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-exposed-udp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
      echo "ip6tables -t raw -A PREROUTING -p udp -m set --match-set ${PROJECT_NAME}-exposed-udp6 dst,dst -m comment --comment \"${IPTABLES_COMMENT}\" -j DROP" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
   fi

   # The query script
   echo >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
   echo "iptables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\"" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script
   echo "ip6tables -t raw -L PREROUTING -n --line-number | grep \"${PROJECT_NAME} Access Control\"" >> ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script

   # Convert multiple consecutive blank lines into one blank line
   sed -i '/^$/N;/^\n$/D' ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script

   echo "[Info] The iptables reject rules have been saved in ${WORKING_DIRECTORY}/.${PROJECT_NAME}-reject-script"
}

#
# [Note] The script will erase all strategies of current docker-compose project immediately
#
remove_iptables_protect_rules() {

   local i=
   
   get_compose_project_name

   for i in $(iptables -t raw -L PREROUTING -n --line-number | grep "${IPTABLES_COMMENT}" | awk '{print $1}' | sort -nr); do
      iptables -t raw -D PREROUTING $i
   done

   for i in $(ip6tables -t raw -L PREROUTING -n --line-number | grep "${IPTABLES_COMMENT}" | awk '{print $1}' | sort -nr); do
      ip6tables -t raw -D PREROUTING $i
   done
}

#
# [Note] Generate ipset records update script. Avoid rebuilding the entire iptables and support adding protection policies directly in the production environment.
#
generate_ipset_update_script() {

   get_compose_project_name
   allow_access_between_compose_containers
   generate_iptables_allow_rules

   sed -e 's#^ipset destroy#ipset flush#g' -e '/^ipset create /d' -e '/iptables -t /d' -e '/ip6tables -t /d' -e '/done/d' ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-allow-script | sed '/^$/N;/^\n$/D' > ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-update-script

   sed -e 's#^ipset destroy#ipset flush#g' -e '/^ipset create /d' -e '/iptables -t /d' -e '/ip6tables -t /d' -e '/done/d' ${WORKING_DIRECTORY}/.${PROJECT_NAME}-allow-script | sed '/^$/N;/^\n$/D' > ${WORKING_DIRECTORY}/.${PROJECT_NAME}-update-script

   echo "[Info] The ipset update rules have been saved in ${WORKING_DIRECTORY}/.${PROJECT_NAME}-preventive-update-script and ${WORKING_DIRECTORY}/.${PROJECT_NAME}-update-script."
}

auto_configure_compose_iptables() {
   :
}

enable_auto_configure_compose_iptables_timer() {

   local currentRealPath=$(realpath $0)
   local templateServicePath=${WORKING_DIRECTORY}/auto-configure-template.service
   local templateTimerPath=${WORKING_DIRECTORY}/auto-configure-template.timer

   if [ ! -f "$templateServicePath" ] || [ ! -f "$templateTimerPath" ]; then
      echo "[Warn] The corresponding template file is missing: $templateServicePath or $templateTimerPath"
      exit -1
   fi

   load_system_service_unit_file_path

   if [ -z "${SYSTEM_SERVICE_UNIT_FILE_PATH}" ]; then
      echo '[Warn] Failed to obtain system service unit file path.'
      exit -1
   fi

   local targetServicePath=${SYSTEM_SERVICE_UNIT_FILE_PATH}/auto-configure-compose-iptables.service
   local targetTimerPath=${SYSTEM_SERVICE_UNIT_FILE_PATH}/auto-configure-compose-iptables.timer

   /usr/bin/cp -f $templateServicePath $targetServicePath
   /usr/bin/cp -f $templateTimerPath $targetTimerPath

   python3 ${WORKING_DIRECTORY}/ini-util.py --write $targetServicePath Unit Description "Auto configure compose iptables"
   python3 ${WORKING_DIRECTORY}/ini-util.py --write $targetServicePath Service ExecStart "/bin/bash $currentRealPath --auto-configure-compose-iptables"
   python3 ${WORKING_DIRECTORY}/ini-util.py --write $targetTimerPath Unit Description "Auto configure secondary IP addresses"
   python3 ${WORKING_DIRECTORY}/ini-util.py --write $targetTimerPath Unit Requires "$(basename $targetServicePath)"

   systemctl daemon-reload
   systemctl enable $(basename $targetServicePath) --now
   systemctl enable $(basename $targetTimerPath) --now

   echo
   systemctl status $(basename $targetServicePath)

   echo
   systemctl status $(basename $targetTimerPath)

   echo
   systemctl list-timers --all --no-page
}

disable_secondary_ip_addresses_timer() {

   load_system_service_unit_file_path

   if [ -z "${SYSTEM_SERVICE_UNIT_FILE_PATH}" ]; then
      echo '[Warn] Failed to obtain system service unit file path.'
      exit -1
   fi

   local targetServicePath=${SYSTEM_SERVICE_UNIT_FILE_PATH}/auto-configure-secondary-ip-addresses.service
   local targetTimerPath=${SYSTEM_SERVICE_UNIT_FILE_PATH}/auto-configure-secondary-ip-addresses.timer

   systemctl disable $(basename $targetServicePath) --now
   systemctl disable $(basename $targetTimerPath) --now

   /usr/bin/rm -f $targetServicePath
   /usr/bin/rm -f $targetTimerPath

   echo "[Info] Both $targetServicePath and $targetTimerPath are disabled and removed."

   echo
   systemctl list-timers --all --no-page
}

####################################
# Function Mappings Area           #
####################################

orderedPara=(
   "--allow-access-between-compose-containers"
   "--generate-port-mapping-tables"
   "--generate-iptables-allow-rules"
   "--generate-iptables-reject-rules"
   "--generate-ipset-update-script"
   "--usage"
)

declare -A mapParaFunc=(
   ["--allow-access-between-compose-containers"]="allow_access_between_compose_containers"
   ["--generate-port-mapping-tables"]="generate_port_mapping_tables"
   ["--generate-iptables-allow-rules"]="generate_iptables_allow_rules"
   ["--generate-iptables-reject-rules"]="generate_iptables_reject_rules"
   ["--generate-ipset-update-script"]="generate_ipset_update_script"
   ["--usage"]="usage"
)

declare -A mapParaSpec=(
   ["--allow-access-between-compose-containers"]="Generate preventive iptables strategies scripts."
   ["--generate-port-mapping-tables"]="Retrieve port exposed surfaces from the static files of the Docker Compose project."
   ["--generate-iptables-allow-rules"]="Generate iptables policy deployment script from Docker Compose project port exposure surface and authorized client IP."
   ["--generate-iptables-reject-rules"]="Generate Iptables Policy Blocking Script from Docker Compose Project Port Exposure Surface."
   ["--generate-ipset-update-script"]="Generate ipset records update script. Avoid rebuilding the entire iptables and support adding protection policies directly in the production environment."
   ["--usage"]="Operation Manual"
)

usage() {
   echo '[Info] Compose Ports Access Controller v1.0'
   echo '[Info] Verified on BCLinux 8.2'
   echo '[Usage]'

   for opt in ${orderedPara[@]}; do
      echo "   $0 $opt   ${mapParaSpec[$opt]}"
   done
}

if [ ! -z "$1" ] && [[ "${!mapParaFunc[@]}" =~ "$1" ]]; then
   INDEX_PARAM=$1
   shift
   eval "${mapParaFunc[${INDEX_PARAM}]} $@"
   exit 0
fi
