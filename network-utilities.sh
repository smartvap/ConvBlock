##############################
# Network Utilities on Linux #
# v1.1                       #
##############################
#!/bin/bash

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

#
# [Note] The common storage and management networks in IaaS are usually isolated from the business data network. The following is sample data, please modify it according to the actual situation.
#
STORAGE_SUBNETS=(10.133.0.0/16)
MANAGEMENT_SUBNETS=(10.121.0.0/16)

#
# [Note] The working path is based on the actual path of the current script, not the current path. Therefore, using the tool's relative or absolute path access in any path will not cause any changes to the working path variable, this design ensures the stability of the working path.
#
WORKING_DIRECTORY=$(dirname $(realpath $0))

#
# [Note] The subnets on Loopback Interface. The system service can listen at address 127.0.0.0/8, so that the service is only available locally and will not be exposed to external networks, improving security. Use ip a show lo to get the subnets addresses. Not strict mode.
#
LOOPBACK_SUBNETS_IPV4=127.0.0.1/8
LOOPBACK_SUBNETS_IPV6=::1/128

#
# [Note] Is IPv6 prioritized
#
PREFER_IPV6=false

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
      result=( ${result[@]} $ipAddr )
   done

   echo "${result[@]}"
}

#
# [Note] Tool function: Convert dotted decimal IP addresses to integers
#
ip_to_int() {
   local IFS='.'
   read -r a b c d <<< "$1"
   echo $((a * 256**3 + b * 256**2 + c * 256 + d))
}

#
# [Note] Tool function: Calculate network address (CIDR notation)
#
calculate_network() {
    local ip="$1"
    local cidr="$2"
    local mask_int=$((0xffffffff << (32 - cidr) & 0xffffffff)) # Calculate the integer form of subnet mask
    local ip_int=$(ip_to_int "$ip")
    local network_int=$((ip_int & mask_int)) # Obtain network address through bitwise AND operation
    # Convert network address integers back to dotted decimal format
    echo "$(( (network_int >> 24) & 0xff )).$(( (network_int >> 16) & 0xff )).$(( (network_int >> 8) & 0xff )).$(( network_int & 0xff ))/$cidr"
}

#
# [Note] Efficient subnet inclusion relationship determination method
#
is_subnet_contained() {

   local subnet1="$1" # Format as 192.168.10.128/25
   local subnet2="$2" # Format as 192.168.10.0/24

   # Extract the IP and CIDR prefix of subnet 1
   local ip1="${subnet1%/*}"
   local cidr1="${subnet1#*/}"

   # Extract the IP and CIDR prefix of subnet 2
   local ip2="${subnet2%/*}"
   local cidr2="${subnet2#*/}"

   # Convert to integer
   local ip1_int=$(ip_to_int "$ip1")
   local ip2_int=$(ip_to_int "$ip2")

   # Calculate the integer form of subnet mask
   local mask1_int=$((0xffffffff << (32 - cidr1) & 0xffffffff))
   local mask2_int=$((0xffffffff << (32 - cidr2) & 0xffffffff))

   # Calculate the integer form of network addresses
   local net1_int=$((ip1_int & mask1_int))
   local net2_int=$((ip2_int & mask2_int))

   # Core conditions for determining ownership:
   # 1. The prefix length of subnet 2 must be less than or equal to the prefix length of subnet 1 (i.e. subnet 2 has a wider mask)
   # 2. After performing a bitwise AND operation on the network address of subnet 1 and the mask of subnet 2, it is equal to the network address of subnet 2
   if [ "$cidr2" -le "$cidr1" ] && [ $((net1_int & mask2_int)) -eq "$net2_int" ]; then
      echo 'true'
   else
      echo 'false'
   fi
}

#
# [Note] Obtain docker subnet addresses. These docker subnets are created by `docker network create` or docker-compose.
#
get_docker_subnet_addresses() {

   IFS=$'\n' DOCKER_NETWORK_SUBNETS=($(docker network inspect $(docker network ls -q 2>/dev/null) 2>/dev/null | jq -r '.[] | .IPAM.Config[].Subnet' 2>/dev/null))

   IFS=' ' DOCKER_NETWORK_SUBNETS=($(standardize_ip_addresses ${DOCKER_NETWORK_SUBNETS[@]}))

   echo '[Info] Docker network subnets are as below:'
   echo ${DOCKER_NETWORK_SUBNETS[@]} | tr ' ' '\n' | grep -v '^$' | sed 's#^#   #g'
   echo

   echo ${DOCKER_NETWORK_SUBNETS[@]} | tr ' ' '\n' > ${WORKING_DIRECTORY}/.docker-networks

   DOCKER_NETWORK_SUBNETS_IPV4=()
   DOCKER_NETWORK_SUBNETS_IPV6=()

   local i=
   for i in ${DOCKER_NETWORK_SUBNETS[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         DOCKER_NETWORK_SUBNETS_IPV4=(${DOCKER_NETWORK_SUBNETS_IPV4[@]} $i)
      elif [ "$ipFamily" == "IPv6" ]; then
         DOCKER_NETWORK_SUBNETS_IPV6=(${DOCKER_NETWORK_SUBNETS_IPV6[@]} $i)
      fi
   done

   echo ${DOCKER_NETWORK_SUBNETS_IPV4[@]} | tr ' ' '\n' > ${WORKING_DIRECTORY}/.docker-networks-ipv4
   echo ${DOCKER_NETWORK_SUBNETS_IPV6[@]} | tr ' ' '\n' > ${WORKING_DIRECTORY}/.docker-networks-ipv6
}

#
# [Note] Dump the K8s cluster/pods CIDRs from calico daemonset resource manifest. K8s Cluster/Pods CIDR. You can obtain this value from ippools, the apiserver process or kube-proxy process. I'm not entirely sure if this is an effective and stable way to obtain it. The approximate specification of this parameter is --cluster-cidr=197.166.0.0/16,fd00:c5a6::/106.
#
dump_cluster_cidr_from_calico_ds() {

   IFS=$'\n' CLUSTER_CIDR_IPV4=($(kubectl get ds calico-node -n kube-system --request-timeout=8s -o json 2>/dev/null | jq -r -c '.spec.template.spec.containers[].env[]|select(.name=="CALICO_IPV4POOL_CIDR")|.value'))
   IFS=$'\n' CLUSTER_CIDR_IPV6=($(kubectl get ds calico-node -n kube-system --request-timeout=8s -o json 2>/dev/null | jq -r -c '.spec.template.spec.containers[].env[]|select(.name=="CALICO_IPV6POOL_CIDR")|.value'))
   CLUSTER_CIDR=(${CLUSTER_CIDR_IPV4[@]} ${CLUSTER_CIDR_IPV6[@]})

   echo '[Info] K8s cluster CIDRs are as below:'
   echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   # The alternative variable names, compatible with other situations
   POD_CIDR_IPV4=(${CLUSTER_CIDR_IPV4[@]})
   POD_CIDR_IPV6=(${CLUSTER_CIDR_IPV6[@]})
   POD_CIDR=(${CLUSTER_CIDR[@]})

   if [ ${#CLUSTER_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv4
   fi

   if [ ${#CLUSTER_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv6
   fi

   if [ ${#CLUSTER_CIDR[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr
   fi
}

#
# [Note] Dump the K8s cluster/pods CIDRs from ippool resource manifest into .cluster-cidr* files, caution: Files with the same name in the working directory will be overwritten without prior notice.
#
dump_cluster_cidr_from_ippool() {

   CLUSTER_CIDR_IPV4=()
   CLUSTER_CIDR_IPV6=()

   local i=
   for i in $(kubectl get ippool --request-timeout=8s -o yaml 2>/dev/null | yq r - items[*].spec.cidr); do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         CLUSTER_CIDR_IPV4=(${CLUSTER_CIDR_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         CLUSTER_CIDR_IPV6=(${CLUSTER_CIDR_IPV6[@]} "$i")
      fi
   done

   CLUSTER_CIDR=(${CLUSTER_CIDR_IPV4[@]} ${CLUSTER_CIDR_IPV6[@]})

   echo '[Info] K8s cluster CIDRs extracted from ippool are as below:'
   echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   if [ ${#CLUSTER_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv4
   fi

   if [ ${#CLUSTER_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv6
   fi

   if [ ${#CLUSTER_CIDR[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr
   fi
}

#
# [Note] Dump the K8s cluster/pods CIDRs from kube-controller-manager intializing command. The --cluster-cidr parameter needs to be configured on kube-controller-manager component in most K8s environments, which is a fallback technique. Note that multiple IPv4/6 addresses can be configured here, but this does not necessarily mean it will take effect.
#
dump_cluster_cidr_from_controller_manager() {

   CLUSTER_CIDR_IPV4=()
   CLUSTER_CIDR_IPV6=()
   IFS=',' CLUSTER_CIDR=($(ps -ef | grep kube-controller-manager | grep 'cluster-cidr' | sed 's#.*--cluster-cidr=\([^ ]*\).*#\1#g'))
   
   local i=
   for i in ${CLUSTER_CIDR[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         CLUSTER_CIDR_IPV4=(${CLUSTER_CIDR_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         CLUSTER_CIDR_IPV6=(${CLUSTER_CIDR_IPV6[@]} "$i")
      fi
   done

   echo '[Info] K8s cluster CIDRs extracted from controller manager are as below:'
   echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   if [ ${#CLUSTER_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv4
   fi

   if [ ${#CLUSTER_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr-ipv6
   fi

   if [ ${#CLUSTER_CIDR[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.cluster-cidr
   fi
}

#
# [Note] The --cluser-cidr parameter is not mandatory for kube-proxy processes.
#
dump_cluster_cidr_from_kube_proxy() {

   CLUSTER_CIDR_IPV4=()
   CLUSTER_CIDR_IPV6=()
   IFS=',' CLUSTER_CIDR=($(ps -ef | grep kube-proxy | grep 'cluster-cidr' | sed 's#.*--cluster-cidr=\([^ ]*\).*#\1#g'))
   
   for i in ${CLUSTER_CIDR[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         CLUSTER_CIDR_IPV4=(${CLUSTER_CIDR_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         CLUSTER_CIDR_IPV6=(${CLUSTER_CIDR_IPV6[@]} "$i")
      fi
   done

   echo '[Info] K8s cluster CIDRs extracted from kube proxy are as below:'
   echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   if [ ${#CLUSTER_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV4[@]}" | tr ' ' '\n' | tee ${WORKING_DIRECTORY}/.cluster-cidr-ipv4
   fi

   if [ ${#CLUSTER_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR_IPV6[@]}" | tr ' ' '\n' | tee ${WORKING_DIRECTORY}/.cluster-cidr-ipv6
   fi

   if [ ${#CLUSTER_CIDR[@]} -ne 0 ]; then
      echo "${CLUSTER_CIDR[@]}" | tr ' ' '\n' | tee ${WORKING_DIRECTORY}/.cluster-cidr
   fi
}

get_cluster_cidr() {

   CLUSTER_CIDR_IPV4=($(cat ${WORKING_DIRECTORY}/.cluster-cidr-ipv4 2>/dev/null))
   CLUSTER_CIDR_IPV6=($(cat ${WORKING_DIRECTORY}/.cluster-cidr-ipv6 2>/dev/null))
   CLUSTER_CIDR=($(cat ${WORKING_DIRECTORY}/.cluster-cidr 2>/dev/null))

   if ! ${PREFER_IPV6}; then

      if [ ${#CLUSTER_CIDR_IPV4[@]} -eq 0 ]; then
         dump_cluster_cidr_from_ippool
      fi

      if [ ${#CLUSTER_CIDR_IPV4[@]} -eq 0 ]; then
         dump_cluster_cidr_from_controller_manager
      fi

      if [ ${#CLUSTER_CIDR_IPV4[@]} -eq 0 ]; then
         dump_cluster_cidr_from_calico_ds
      fi

      if [ ${#CLUSTER_CIDR_IPV4[@]} -eq 0 ]; then
         dump_cluster_cidr_from_kube_proxy
      fi
   
   else

      if [ ${#CLUSTER_CIDR_IPV6[@]} -eq 0 ]; then
         dump_cluster_cidr_from_ippool
      fi

      if [ ${#CLUSTER_CIDR_IPV6[@]} -eq 0 ]; then
         dump_cluster_cidr_from_controller_manager
      fi

      if [ ${#CLUSTER_CIDR_IPV6[@]} -eq 0 ]; then
         dump_cluster_cidr_from_calico_ds
      fi

      if [ ${#CLUSTER_CIDR_IPV6[@]} -eq 0 ]; then
         dump_cluster_cidr_from_kube_proxy
      fi
   
   fi
}

dump_service_cidr_from_controller_manager() {

   SERVICE_CIDR_IPV4=()
   SERVICE_CIDR_IPV6=()
   IFS=',' SERVICE_CIDR=($(ps -ef | grep kube-controller-manager | grep '\--service-cluster-ip-range' | sed 's#.*--service-cluster-ip-range=\([^ ]*\).*#\1#g'))
   
   local i=
   for i in ${SERVICE_CIDR[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         SERVICE_CIDR_IPV4=(${SERVICE_CIDR_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         SERVICE_CIDR_IPV6=(${SERVICE_CIDR_IPV6[@]} "$i")
      fi
   done

   echo '[Info] K8s service CIDRs extracted from controller manager are as below:'
   echo "${SERVICE_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   if [ ${#SERVICE_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.service-cidr-ipv4
   fi

   if [ ${#SERVICE_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.service-cidr-ipv6
   fi

   if [ ${#SERVICE_CIDR[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.service-cidr
   fi
}

dump_service_cidr_from_kube_apiserver() {

   SERVICE_CIDR_IPV4=()
   SERVICE_CIDR_IPV6=()
   IFS=',' SERVICE_CIDR=($(ps -ef | grep kube-apiserver | grep '\--service-cluster-ip-range' | sed 's#.*--service-cluster-ip-range=\([^ ]*\).*#\1#g'))
   
   local i=
   for i in ${SERVICE_CIDR[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family $i)
      if [ "$ipFamily" == "IPv4" ]; then
         SERVICE_CIDR_IPV4=(${SERVICE_CIDR_IPV4[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         SERVICE_CIDR_IPV6=(${SERVICE_CIDR_IPV6[@]} "$i")
      fi
   done

   echo '[Info] K8s service CIDRs extracted from kube apiserver are as below:'
   echo "${SERVICE_CIDR[@]}" | tr ' ' '\n' | sed 's#^#   #g'

   if [ ${#SERVICE_CIDR_IPV4[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.service-cidr-ipv4
   fi

   if [ ${#SERVICE_CIDR_IPV6[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR_IPV6[@]}" | tr ' ' '\n' | tee ${WORKING_DIRECTORY}/.service-cidr-ipv6
   fi

   if [ ${#SERVICE_CIDR[@]} -ne 0 ]; then
      echo "${SERVICE_CIDR[@]}" | tr ' ' '\n' | tee ${WORKING_DIRECTORY}/.service-cidr
   fi
}

get_service_cidr() {

   SERVICE_CIDR_IPV4=($(cat ${WORKING_DIRECTORY}/.service-cidr-ipv4 2>/dev/null))
   SERVICE_CIDR_IPV6=($(cat ${WORKING_DIRECTORY}/.service-cidr-ipv6 2>/dev/null))
   SERVICE_CIDR=($(cat ${WORKING_DIRECTORY}/.service-cidr 2>/dev/null))

   if ! ${PREFER_IPV6}; then

      if [ ${#SERVICE_CIDR_IPV4[@]} -eq 0 ]; then
         dump_service_cidr_from_kube_apiserver
      fi

      if [ ${#SERVICE_CIDR_IPV4[@]} -eq 0 ]; then
         dump_service_cidr_from_controller_manager
      fi
   
   else

      if [ ${#SERVICE_CIDR_IPV6[@]} -eq 0 ]; then
         dump_service_cidr_from_kube_apiserver
      fi

      if [ ${#SERVICE_CIDR_IPV6[@]} -eq 0 ]; then
         dump_service_cidr_from_controller_manager
      fi

   fi
}

#
# [Note] KVM Virtual Network IP addresses. The name of the KVM virtual network card can be specified arbitrarily, not limited to virbr_, so it should be obtained using professional management tools.
#
get_kvm_subnet_addresses() {

   KVM_SUBNET_ADDRESSES=()
   KVM_SUBNET_ADDRESSES_IPV4=()
   KVM_SUBNET_ADDRESSES_IPV6=()

   local i=
   local ipAddress=
   local ipNetmask=
   local subnet=

   for i in $(virsh net-list --name --all | grep -v '^$'); do
      ipAddress=$(virsh net-dumpxml $i | xmllint --xpath 'string(/network/ip/@address)' -)
      ipNetmask=$(virsh net-dumpxml $i | xmllint --xpath 'string(/network/ip/@netmask)' -)
      if [ ! -z "$ipAddress" ] && [ ! -z "$ipNetmask" ]; then
         subnet=$(standardize_ip_address "$ipAddress/$ipNetmask")
         if [ ! -z "$subnet" ]; then
            KVM_SUBNET_ADDRESSES=( ${KVM_SUBNET_ADDRESSES[@]} "$subnet" )
         fi
      fi
   done

   echo '[Info] KVM network IP addresses are as below:'
   echo ${KVM_SUBNET_ADDRESSES[@]} | tr ' ' '\n' | grep -v '^$' | sed 's#^#   #g'
   echo

   echo ${KVM_SUBNET_ADDRESSES[@]} | tr ' ' '\n' > .kvm-networks

   for i in ${KVM_SUBNET_ADDRESSES[@]}; do
      local ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family "$i")
      if [ "$ipFamily" == "IPv4" ]; then
         KVM_SUBNET_ADDRESSES_IPV4=(${KVM_SUBNET_ADDRESSES[@]} "$i")
      elif [ "$ipFamily" == "IPv6" ]; then
         KVM_SUBNET_ADDRESSES_IPV6=(${KVM_SUBNET_ADDRESSES[@]} "$i")
      fi
   done

   if [ ${#KVM_SUBNET_ADDRESSES_IPV4[@]} -ne 0 ]; then
      echo "${KVM_SUBNET_ADDRESSES_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.kvm-networks-ipv4
   fi

   if [ ${#KVM_SUBNET_ADDRESSES_IPV6[@]} -ne 0 ]; then
      echo "${KVM_SUBNET_ADDRESSES_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.kvm-networks-ipv6
   fi
}

#
# [Note] Reload VMware subnet addresses. vmnet* network card names are automatically generated and managed by VMware Workstation and cannot be modified by oneself.
#
get_vmware_subnet_addresses() {

   VMWARE_SUBNET_ADDRESSES=()
   VMWARE_SUBNET_ADDRESSES_IPV4=()
   VMWARE_SUBNET_ADDRESSES_IPV6=()

   local i=
   for i in $(ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | grep '^vmnet'); do
      local ipv4Subnets=($(ip addr show dev "$i" | grep -w 'inet' | awk '{print $2}'))
      local ipv6Subnets=($(ip addr show dev "$i" | grep -w 'inet6' | grep -v "fe80" | awk '{print $2}'))
      VMWARE_SUBNET_ADDRESSES=( ${VMWARE_SUBNET_ADDRESSES[@]} ${ipv4Subnets[@]} ${ipv6Subnets[@]} )
      VMWARE_SUBNET_ADDRESSES_IPV4=( ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${ipv4Subnets[@]} )
      VMWARE_SUBNET_ADDRESSES_IPV6=( ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${ipv6Subnets[@]} )
   done

   VMWARE_SUBNET_ADDRESSES=($(standardize_ip_addresses ${VMWARE_SUBNET_ADDRESSES[@]}))
   VMWARE_SUBNET_ADDRESSES_IPV4=($(standardize_ip_addresses ${VMWARE_SUBNET_ADDRESSES_IPV4[@]}))
   VMWARE_SUBNET_ADDRESSES_IPV6=($(standardize_ip_addresses ${VMWARE_SUBNET_ADDRESSES_IPV6[@]}))

   echo '[Info] VMware subnet addresses are as below:'
   echo ${VMWARE_SUBNET_ADDRESSES[@]} | tr ' ' '\n' | grep -v '^$' | sed 's#^#   #g'
   echo

   if [ ${#VMWARE_SUBNET_ADDRESSES_IPV4[@]} -ne 0 ]; then
      echo "${VMWARE_SUBNET_ADDRESSES_IPV4[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.vmware-networks-ipv4
   fi

   if [ ${#VMWARE_SUBNET_ADDRESSES_IPV6[@]} -ne 0 ]; then
      echo "${VMWARE_SUBNET_ADDRESSES_IPV6[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.vmware-networks-ipv6
   fi

   if [ ${#VMWARE_SUBNET_ADDRESSES[@]} -ne 0 ]; then
      echo "${VMWARE_SUBNET_ADDRESSES[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.vmware-networks
   fi
}

#
# Get external IP addresses. Here, a strict two-layer filtering mode is adopted. The first layer filters based on the prefix of the network card name. Since this prefix is not sufficient to cover all private networks, the second layer of filtering needs to be performed again based on the internal private address. For example, KVM's virbr_ can completely define the network card name by itself.
#
get_external_ip_addresses() {

   # Reset the external IP addresses global variable
   EXTERNAL_IP_ADDRESSES=()
   EXTERNAL_IPV4_ADDRESSES=()
   EXTERNAL_IPV6_ADDRESSES=()

   # Load 3rd-party virtual network IP addresses
   get_docker_subnet_addresses
   get_cluster_cidr
   get_service_cidr
   get_kvm_subnet_addresses
   get_vmware_subnet_addresses

   # Merge all virtual network IP addresses
   INTERNAL_SUBNET_ADDRESSES=( ${DOCKER_NETWORK_SUBNETS[@]} ${CLUSTER_CIDR[@]} ${SERVICE_CIDR[@]} ${KVM_SUBNET_ADDRESSES[@]} ${VMWARE_SUBNET_ADDRESSES[@]} ${STORAGE_SUBNETS[@]} ${MANAGEMENT_SUBNETS[@]})
   
   # Get all IP addresses of all physical or bonding interfaces. By filtering known virtual bridges, the purpose of this step is to supplement and improve the internal subnet addresses previously sorted out
   local i=
   local j=
   for i in $(ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | grep -vE '^lo$|^vmnet|^virbr|^br|^tun|^tap|^veth|^docker|^vnet|^cali|^flannel|^vxlan|^kube-ipvs|^dummy'); do
      local ipv4Addresses=($(ip addr show dev "$i" | grep -w "inet" | sed 's#.*inet \([^/]*\)/[0-9]*.*#\1#g'))
      local ipv6Addresses=($(ip addr show dev "$i" | grep -w "inet6" | grep -v 'fe80' | sed 's#.*inet6 \([^/]*\)/[0-9]*.*#\1#g'))
      for j in ${ipv4Addresses[@]}; do
         local isPrivate=$(python3 network-utilities.py --check-ip-in-pools $j ${INTERNAL_SUBNET_ADDRESSES[@]} | tr '[:upper:]' '[:lower:]')
         if ! $isPrivate; then
            EXTERNAL_IPV4_ADDRESSES=( ${EXTERNAL_IPV4_ADDRESSES[@]} $j )
         fi
      done
      for j in ${ipv6Addresses[@]}; do
         local isPrivate=$(python3 network-utilities.py --check-ip-in-pools $j ${INTERNAL_SUBNET_ADDRESSES[@]} | tr '[:upper:]' '[:lower:]')
         if ! $isPrivate; then
            EXTERNAL_IPV6_ADDRESSES=( ${EXTERNAL_IPV6_ADDRESSES[@]} $j )
         fi
      done
   done

   # Merge
   EXTERNAL_IP_ADDRESSES=( ${EXTERNAL_IPV4_ADDRESSES[@]} ${EXTERNAL_IPV6_ADDRESSES[@]})

   echo '[Info] All external IP addresses of this host are as below:'
   echo ${EXTERNAL_IP_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#   #g'
   echo

   # Save external IP addresses
   if [ ${#EXTERNAL_IPV4_ADDRESSES[@]} -ne 0 ]; then
      echo "${EXTERNAL_IPV4_ADDRESSES[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.external-ipv4
   fi

   if [ ${#EXTERNAL_IPV6_ADDRESSES[@]} -ne 0 ]; then
      echo "${EXTERNAL_IPV6_ADDRESSES[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.external-ipv6
   fi

   if [ ${#EXTERNAL_IP_ADDRESSES[@]} -ne 0 ]; then
      echo "${EXTERNAL_IP_ADDRESSES[@]}" | tr ' ' '\n' > ${WORKING_DIRECTORY}/.external-ip
   fi

}

#
# [Note] The addresses marked as secondary are often floating addresses that can be dynamically added and removed by specific services such as keepalived, Pacemaker, etc.
#
get_additional_ip_addresses() {

   IFS=$'\n' ADDITIONAL_IPV4_ADDRESSES=($(ip addr | grep -w 'secondary' | grep -w 'inet' | sed 's#.*inet \([^/]*\)/[0-9]*.*#\1#g'))
   IFS=$'\n' ADDITIONAL_IPV6_ADDRESSES=($(ip addr | grep -w 'secondary' | grep -w 'inet6' | grep -v 'fe80' | sed 's#.*inet6 \([^/]*\)/[0-9]*.*#\1#g'))

   if [ ${#ADDITIONAL_IPV4_ADDRESSES[@]} -ne 0 ]; then
      (IFS=$'\n'; echo "${ADDITIONAL_IPV4_ADDRESSES[*]}") > .addtitional-ipv4
   fi

   if [ ${#ADDITIONAL_IPV6_ADDRESSES[@]} -ne 0 ]; then
      (IFS=$'\n'; echo "${ADDITIONAL_IPV6_ADDRESSES[*]}") > .addtitional-ipv6
   fi

   ADDITIONAL_IP_ADDRESSES=( ${ADDITIONAL_IPV4_ADDRESSES[@]} ${ADDITIONAL_IPV6_ADDRESSES[@]} )
   if [ ${#ADDITIONAL_IP_ADDRESSES[@]} -ne 0 ]; then
      (IFS=$'\n'; echo "${ADDITIONAL_IP_ADDRESSES[*]}") > .addtitional-ip
   fi

   echo '[Info] All additional IP addresses of this host are as below:'
   echo ${ADDITIONAL_IP_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#   #g'
}

#
# [Note] Save CURRENT_IP environment variable in .env file. The CURRENT_IP is the first non secondary IP of the host's default routing network interface.
#
get_current_ip_environment() {

   # Option 1: Attempt to extract from the default routing network interface
   DEFAULT_NETWORK_INTERFACE=$(ip $([ "$PREFER_IPV6" = "true" ] && echo "-6") route | awk '$1 == "default" {print $5}')
   echo "[Info] The default routing network interface name is: ${DEFAULT_NETWORK_INTERFACE}."

   # If obtaining the default routing network card fails, it means that option 2 needs to be taken, which is to extract from the external address list
   if [ ! -z "${DEFAULT_NETWORK_INTERFACE}" ]; then

      CURRENT_IPV4=$(ip a show dev ${DEFAULT_NETWORK_INTERFACE} | grep -w 'inet' | grep -v -w 'secondary' | sed 's#.*inet \([^/]*\)/[0-9]*.*#\1#g' | head -1)
      echo "[Info] The primary IPv4 address of ${DEFAULT_NETWORK_INTERFACE} is ${CURRENT_IPV4:-<empty>}."

      IFS=$'\n' ADDITIONAL_IPV4=($(ip a show dev ${DEFAULT_NETWORK_INTERFACE} | grep -w 'inet' | grep -w 'secondary' | sed 's#.*inet \([^/]*\)/[0-9]*.*#\1#g'))
      echo "[Info] The additional IPv4 addresses of ${DEFAULT_NETWORK_INTERFACE} is ${ADDITIONAL_IPV4[@]:-<empty>}."

      CURRENT_IPV6=$(ip a show dev ${DEFAULT_NETWORK_INTERFACE} | grep -w 'inet6' | grep -v -w 'secondary' | grep -v 'fe80' | sed 's#.*inet6 \([^/]*\)/[0-9]*.*#\1#g' | head -1)
      echo "[Info] The primary IPv6 address of ${DEFAULT_NETWORK_INTERFACE} is ${CURRENT_IPV6:-<empty>}."

      IFS=$'\n' ADDITIONAL_IPV6=($(ip a show dev ${DEFAULT_NETWORK_INTERFACE} | grep -w 'inet6' | grep -w 'secondary' | grep -v 'fe80' | sed 's#.*inet6 \([^/]*\)/[0-9]*.*#\1#g'))

      [ "${PREFER_IPV6}" = "false" ] && CURRENT_IP=${CURRENT_IPV4}
      [ "${PREFER_IPV6}" = "false" ] && ADDITIONAL_IP=( ${ADDITIONAL_IPV4[@]} )
      [ "${PREFER_IPV6}" = "true" ] && CURRENT_IP=${CURRENT_IPV6}
      [ "${PREFER_IPV6}" = "true" ] && ADDITIONAL_IP=( ${ADDITIONAL_IPV6[@]} )
      
      # Successfully writing the file means that option 1 has been successfully implemented
      if [ ! -z "${CURRENT_IP}" ]; then
         touch .env
         sed -i '/CURRENT_IP = /d' .env
         echo "CURRENT_IP = ${CURRENT_IP}" | tee -a .env
      fi

      if [ ${#ADDITIONAL_IP[@]} -ne 0 ]; then
         touch .env
         sed -i '/ADDITIONAL_IP_/d' .env
         local i=0
         local j=
         for j in ${ADDITIONAL_IP[@]}; do
            echo "ADDITIONAL_IP_$i = $j" | tee -a .env
            i=$(expr $i + 1)
         done
      fi

      return
   fi

   # Option 2: Attempt to extract from the external IP addresses
   
   get_external_ip_addresses
   get_additional_ip_addresses

   local intersection=()
   local different_set=()

   if ! ${PREFER_IPV6}; then
      IFS=$'\n' intersection=($(echo ${EXTERNAL_IPV4_ADDRESSES[@]} ${ADDITIONAL_IPV4_ADDRESSES[@]} | sed 's# #\n#g' | sort | uniq -d))
      IFS=$'\n' different_set=($(echo ${EXTERNAL_IPV4_ADDRESSES[@]} ${intersection[@]} | sed 's# #\n#g' | sort | uniq -u))
   else
      IFS=$'\n' intersection=($(echo ${EXTERNAL_IPV6_ADDRESSES[@]} ${ADDITIONAL_IPV6_ADDRESSES[@]} | sed 's# #\n#g' | sort | uniq -d))
      IFS=$'\n' different_set=($(echo ${EXTERNAL_IPV6_ADDRESSES[@]} ${intersection[@]} | sed 's# #\n#g' | sort | uniq -u))
   fi

   if [ ${#different_set[@]} -ne 0 ]; then
      touch .env
      sed -i '/CURRENT_IP = /d' .env
      echo "CURRENT_IP = ${different_set[0]}" | tee -a .env
   fi

   if [ ${#ADDITIONAL_IP_ADDRESSES[@]} -ne 0 ]; then
      touch .env
      sed -i '/ADDITIONAL_IP_/d' .env
      local i=0
      local j=
      for j in ${ADDITIONAL_IP_ADDRESSES[@]}; do
         echo "ADDITIONAL_IP_$i = $j" | tee -a .env
         i=$(expr $i + 1)
      done
   fi
}

#
# [Note] Dump the name of the business data network card (usually an external network adapter) to the local working directory
#
get_external_interfaces() {

   > ${WORKING_DIRECTORY}/.external-interfaces

   for iface in $(ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | grep -vE '^lo$|^vmnet|^virbr|^br|^tun|^tap|^veth|^docker|^vnet|^cali|^flannel|^vxlan'); do

      local ipv4Addr=$(ip -4 addr show dev "$iface" 2>/dev/null | grep inet | awk '{print $2}')
      # Check IPv6 address (global unicast address)
      local ipv6Addr=$(ip -6 addr show dev "$iface" 2>/dev/null | grep inet6 | grep -v fe80:: | awk '{print $2}')
    
      if [ ! -z "$ipv4Addr" ] || [ ! -z "$ipv6Addr" ]; then
         echo $iface >> ${WORKING_DIRECTORY}/.external-interfaces
      fi
   done
}

#
# [Note] A example of .secondary-addresses is : [{"bond0":["134.84.62.35/24","134.84.62.36/24","134.84.62.37/24","134.84.62.38/24","134.84.62.39/24"]}], don't forget to add the mask.
# Use this command to modify this config file: echo '[{"bond0":["134.84.62.35/24","134.84.62.36/24","134.84.62.37/24","134.84.62.38/24","134.84.62.39/24"]}]' | jq -r . | tee .secondary-addresses
#
add_secondary_addresses() {
   
   if [ ! -f .secondary-addresses ]; then
      echo '[Info] The configuration file .secondary-addresses does not exist.'
      exit -1
   fi

   for i in $(jq -r -c .[] .secondary-addresses); do
      local ifname=$(echo $i | jq -r -c 'keys[0]')
      local ipaddrs=($(echo $i | jq -r -c .$ifname[]))
      for j in ${ipaddrs[@]}; do
         local k="ip addr add $j dev $ifname"
         eval "$k"
         echo "[Info] $k √"
      done
   done
}

del_secondary_addresses() {

   if [ ! -f .secondary-addresses ]; then
      echo '[Info] The configuration file .secondary-addresses does not exist.'
      exit -1
   fi

   for i in $(jq -r -c .[] .secondary-addresses); do
      local ifname=$(echo $i | jq -r -c 'keys[0]')
      local ipaddrs=($(echo $i | jq -r -c .$ifname[]))
      for j in ${ipaddrs[@]}; do
         local k="ip addr del $j dev $ifname"
         eval "$k"
         echo "[Info] $k √"
      done
   done
}

orderedPara=(
   "--is-subnet-contained"
   "--save-external-ip-addresses"
   "--save-additional-ip-addresses"
   "--save-current-ip-environment"
   "--save-external-interfaces"
   "--save-docker-network-ip-addresses"
   "--add-secondary-addresses"
   "--del-secondary-addresses"
   "--usage"
)

declare -A mapParaFunc=(
   ["--is-subnet-contained"]="is_subnet_contained"
   ["--save-external-ip-addresses"]="save_external_ip_addresses"
   ["--save-additional-ip-addresses"]="save_additional_ip_addresses"
   ["--save-current-ip-environment"]="save_current_ip_environment"
   ["--save-external-interfaces"]="save_external_interfaces"
   ["--save-docker-network-ip-addresses"]="load_docker_network_ip_addresses"
   ["--add-secondary-addresses"]="add_secondary_addresses"
   ["--del-secondary-addresses"]="del_secondary_addresses"
   ["--usage"]="usage"
)

declare -A mapParaSpec=(
   ["--is-subnet-contained"]="Use this option to check if one subnet belongs to another."
   ["--save-external-ip-addresses"]="Use this option to save all external IP addresses to a specified hidden file: .external-ip."
   ["--save-additional-ip-addresses"]="Use this option to save all additional IP addresses to a specified hidden file: .additional-ip."
   ["--save-current-ip-environment"]="Use this option to save CURRENT_IP environment variable to .env file."
   ["--save-external-interfaces"]="Use this option to save the business data network card (usually an external network adapter) to .external-interfaces file."
   ["--save-docker-network-ip-addresses"]="Use this option to save docker network IP addresses to .docker-networks file."
   ["--add-secondary-addresses"]="Add secondary addresses based on the configuration data in the file .secondary-addresses."
   ["--del-secondary-addresses"]="Remove secondary addresses based on the configuration data in the file .secondary-addresses."
   ["--usage"]="Operation Manual"
)

usage() {
   echo '[Info] Network Utilities v1.0'
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