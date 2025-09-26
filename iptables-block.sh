###################################
# IPTABLES BLOCKER       v240313  #
# paragon.cmcc.com                #
###################################

#!/bin/bash

# [Note] Packets dump --> Analyze --> Block IPTABLES

#########################################
# Bugs, Defects and Other Problems      #
#########################################

# [1] There is a case where port forwarding is configured on iptables, but the listening port on the current node cannot be seen through netstat. [Done]
# [2] Analyzing processes of each listening port. [Done]
# [3] When the container on the current node accesses open services on the current node, due to the dynamic nature of the container IP, the address segments of the container network, such as the bip address segment and all address segments under the Docker network, such as the kube apiserver service port, should be released. This function is not universal, therefore it is not included as a regular function.
# [4] The intercepted request can be correctly identified and the connection failure caused by security protection can be found in time.
# [5] Iptables automatically takes effect after the host is restarted.
# [6] Add manually backup functions
# [7] udp is not properly handled!
# [8] multiport optimize

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

#########################################
# Dependency components detection area  #
#########################################

if [ -z "`which tcpdump 2>/dev/null`" ]; then
   yum -y install tcpdump
   if [ -z "`which tcpdump 2>/dev/null`" ]; then
      echo '[Warn] Failed to install tcpdump!'
      exit 1
   fi
fi

if [ -z "`which lsof 2>/dev/null`" ]; then
   yum -y install lsof
   if [ -z "`which lsof 2>/dev/null`" ]; then
      echo '[Warn] Failed to install lsof!'
      exit 1
   fi
fi

if [ -z "`which jq 2>/dev/null`" ]; then
   yum -y install jq
   if [ -z "`which jq 2>/dev/null`" ]; then
      echo '[Warn] Failed to install jq!'
      exit 1
   fi
fi

if [ -z "`which python2 2>/dev/null`" ]; then
   yum -y install python2
   if [ -z "`which python2 2>/dev/null`" ]; then
      echo '[Warn] Failed to install python2!'
      exit 1
   fi
fi

if [ -z "`which pip2 2>/dev/null`" ]; then
   yum -y install python2-pip
   if [ -z "`which pip2 2>/dev/null`" ]; then
      echo '[Warn] Failed to install pip2!'
      exit 1
   fi
fi

pip2 show ipaddress -q 2>/dev/null
if [ $? -ne 0 ]; then
   pip2 install ipaddress-1.0.23-py2.py3-none-any.whl -q 2>/dev/null
   exit 0
fi

#########################################
# Global Variables Setting Area         #
#########################################

#
# 1. List of virtual network adapter name prefixes that should be ignored.
#
ignIfNames=(

   # These network cards typically represent bridges in Linux systems, used to connect different network devices or containers. In Kubernetes, common container network solutions such as Flannel, Calico, etc. create such bridges to achieve communication between containers.
   '^br-'

   # These network cards are generally created by Calico container network solutions to facilitate communication between containers and implement network policies. Calico uses the BGP protocol to route traffic between containers and provides network security features.
   '^cali'

   # The Docker container engine creates a network bridge by default, which is used to connect the Docker container and the host's network. Communication between Docker containers and with external networks will take place through this bridge.
   '^docker'

   # This type of network card is typically used for tunneling technology to transmit data packets between different networks. In Kubernetes, some network solutions may use tunneling techniques to connect containers on different nodes.
   '^tunl'

   # These network cards are virtual Ethernet devices used to connect different network namespaces in Linux systems. In a container, there is usually a pair of Veth devices, one connected to the interior of the container and the other connected to the host's bridge or other network devices.
   '^veth'

   # Flannel is a common container network solution that creates network card adapters starting with Flannel in Kubernetes clusters to enable communication and network connectivity between containers.
   '^flannel'

   # CNI (Container Network Interface) is a standard interface for container networks, and many container network solutions follow this standard. In Kubernetes, the CNI plugin creates network card adapters starting with CNI, which are used to configure and manage container networks.
   '^cni'

   # Open vSwitch (OVS) is a virtual switch software used for network virtualization and software defined networks (SDNs). In the Kubernetes cluster, some network solutions may use OVS to create network card adapters starting with OVS.
   '^ovs'

   # VXLAN (Virtual Extensible LAN) is a virtualization extended LAN technology used to implement virtual networks across physical networks. In Kubernetes clusters, some network solutions may create network card adapters starting with vxlan to enable communication between containers.
   '^vxlan'

   # Weave is another common container network solution that creates network card adapters starting with weave in the Kubernetes cluster to enable communication and network connectivity between containers.
   '^weave'

   # Cilium is a network solution for containers and microservices, which creates network card adapters starting with Cilium in Kubernetes clusters to achieve high-performance container network connections.
   '^cilium'

   # Anterea is a container network solution based on OVS, which will create a network card adapter starting with Anterea in Kubernetes cluster to realize network communication between containers.
   '^antrea'

   # Macvlan is a container networking technology that allows containers to directly use physical network interfaces and may create network card adapters starting with macvlan in Kubernetes clusters.
   '^macvlan'

   # In some network tunnels or virtualization configurations, the names of network card adapters beginning with tun or tap may appear to realize the connection and communication of virtual network devices.
   '^tun'
   '^tap'

   # Virtual Bridges for KVM
   '^virbr'

   # Loopback
   '^lo$'
)

#
# 2. Continuous packet capture duration in seconds
#
duration=30

#
# 3. All nodes' IP configurations. This configuration is automatically managed by scripts, please do not manually modify it! The following is a sample configuration, which will be automatically updated when subsequent functions are executed.
#
nodes=(
   192.168.80.11
   192.168.80.12
   192.168.80.13
   192.168.80.14
   192.168.80.15
)

#
# 4. Current Node's IP. When a backup task is assigned to a node, the IP address of the node can be determined based on the intersection of the IP addresses of the K8s node and all network IP addresses of the current node.
#
currNodeIP=192.168.80.11

#
# 5. The CIDR of K8s pods
#
podCidr=

#
# 6. The Work Folder
#
workDir=$(pwd)

#########################################
# Common Routines / Functions area      #
#########################################

#
# 1. A general method for setting list type parameters, used to set the array parameter values in the current shell script. The first parameter is the array name, such as nodes for nodes=(), the second parameter is the value, such as ${nodes[@]}
#
set_list_vals() {
   
   paras=($*)
   arrName=$1
   arrVal=${paras[@]:1}

   if [ -z $arrName ] || [ ${#arrVal[@]} -eq 0 ]; then
      echo '[Warn] Non compliant in-params!'
      exit 1
   fi
   
   # Convert node list to explicit line break format, such as: '   192.168.122.41\n   192.168.122.42\n   192.168.122.43', also named escaped value
   escArrVal=$(echo "${arrVal[@]}" | sed 's# #\\n   #g' | sed 's#^#   #g')

   # The line numbers of matched lines
   arrLines=(`awk '/^'$arrName'=\(/{print NR}' $0`)
   if [ ${#arrLines[@]} -gt 1 ]; then
      echo '[Warn] Multiple configurations of '$arrName' were found in this script. Please remove the conflicting configurations and keep only one item!'
      exit 1
   elif [ ${#arrLines[@]} -eq 0 ]; then
      echo '[Warn] Cannot find the configuration of '$arrName' in this script!'
      exit 1
   fi

   # Navigate to the line number where '<arrName>=(' first appeared
   n1=${arrLines[0]}

   # Delete all single line mode list types, such as nodes=( 192.168.0.1 192.168.0.2 ), the writing does not comply with the specifications, should be removed.
   sed -i '/^'$arrName'=(.*)/d' $0

   # Navigate to the line number where '<arrName>=(' first appeared, once again.
   n2=`awk '/^'$arrName'=\(/{print NR;exit;}' $0`
   if [ -z $n2 ]; then
      sed -i "$n1 i $arrName=(\n)" $0
   fi

   # Remove the original data
   sed -i '/^'$arrName'=(/,/)/{/^'$arrName'=(/!{/)/!d}}' $0

   # Navigate to the inserted row
   n=`expr $n1 + 1`
  
   # Perform insert operations
   sed -i "$n i \\$escArrVal" $0
   # echo "[Info] Dear Excellency: Your configuration was saved in $0, please kindly keep it safe!"
   # echo -ne "[Info] The following is a list of $arrName:\n$escArrVal\n"
   # echo -ne '[Info] Total: '`expr $(echo -ne $escArrVal | wc -l) + 1`' elements.\n'
}

ports_range() {
   
   local ports=($*)
   local startPort=${ports[0]}
   local endPort=${ports[0]}

   for port in "${ports[@]:1}"; do
      if ((port == endPort + 1)); then
         endPort=$port
      else
         if ((startPort == endPort)); then
            echo -n "$startPort "
         else
            echo -n "$startPort-$endPort "
         fi
         startPort=$port
         endPort=$port
      fi
   done

   # The last port range
   if ((startPort == endPort)); then
      echo "$startPort"
   else
      echo "$startPort-$endPort"
   fi
}

#
# 2. Get IP of all nodes. The current function adopts a passive update method. If the acquisition of the K8s node IP address table fails due to abnormalities, the original data will be retained and not overwritten.
#
get_nodes() {

   # The IP of all nodes obtained online
   local onlNodes=($(kubectl get node --request-timeout=8s -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address' | sort -u))

   if [ ${#onlNodes[@]} -ne 0 ]; then
      # Overwrite local persistent deployment data with dynamically obtained data
      nodes=(${onlNodes[@]})
      set_list_vals "nodes" "${nodes[@]}"
   fi

   if [ ${#nodes[@]} -eq 0 ]; then
      echo '[Warn] Cannot find any nodes in this k8s cluster! The current functionality relies on the K8s core process to be running!'
      exit 1
   fi
}

#
# 3. Get the IP of current node
#
get_curr_node_ip() {

   # Remove the previous settings
   currNodeIP=
   perl -p -i -e 's/^currNodeIP=.*/currNodeIP=/g' $0

   # Obtain K8s cluster nodes' IP
   get_nodes

   if [ ${#nodes[@]} -eq 0 ]; then
      exit 1
   fi

   # Obtain all IPs of all interfaces
   local ipArr=(`ip a | grep inet | grep -E -o '([0-9a-fA-F:]+)/[0-9]{1,3}|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -F'/' '{print $1}' | grep -vE '127.0.0.1|::1' | sort | uniq`)

   if [ ${#ipArr[@]} -eq 0 ]; then
      echo '[Warn] Cannot obtain the IPs of all interfaces!'
      exit 1
   fi

   # Solving the intersection of K8s cluster node IP and current node interface IP
   local intersect=(`echo ${nodes[*]} ${ipArr[*]} | sed 's/ /\n/g' | sort | uniq -c | awk '$1!=1{print $2}'`)

   if [ ${#intersect[@]} -gt 1 ]; then
      echo '[Warn] A node should not have more than 1 K8s cluster node IPs!'
      exit 1
   elif [ ${#intersect[@]} -eq 0 ]; then
      echo '[Warn] Although the current node has K8s management permissions, it does not belong to the K8s node.'
      exit 1
   fi

   currNodeIP=${intersect[@]:0:1}
   perl -p -i -e "s/^currNodeIP=.*/currNodeIP=$currNodeIP/g" $0
}

#
# 3. Obtain IP addresses of effective network interfaces
#
get_host_ip_arr() {

   # The expression of ignored interface names
   local expIfNames=`echo ${ignIfNames[@]} | sed 's/ /|/g'`

   # The effective interface names
   local effIfNames=(`ip link show | grep -E '^[0-9]+:' | sed 's/^[0-9^\ ]*: \(.*\):.*/\1/g' | grep -vE $expIfNames`)

   local arrIpLocal=()
   for ifName in ${effIfNames[@]}; do
      arrIpLocal+=(`ip address show $ifName | grep inet | grep -E -o '([0-9a-fA-F:]+)/[0-9]{1,3}|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -F'/' '{print $1}' | grep -vE '127.0.0.1|::1' | sort | uniq`)
   done

   echo ${arrIpLocal[@]}
}

#
# 4. Obtain the pods CIDR through calico-node yamls
#
get_pod_cidr() {

   podCidr=`kubectl get ds calico-node -n kube-system --request-timeout=8s -o json 2>/dev/null | jq -r -c '.spec.template.spec.containers[].env[]|select(.name=="CALICO_IPV4POOL_CIDR")|.value' | head -1`

   perl -p -i -e "s#^podCidr=.*#podCidr=$podCidr#g" $0
}

#
# 5. Start host captures for all listening addresses
#
run_host_caps() {

   # The assembled filter
   local filter=

   # Perform a inspection of all addresses of all interfaces. Loopback network is not controlled by iptables and will be no longer considered!
   local arrIpLocal=(`get_host_ip_arr`)

   # Assember the dst host filter
   filter='('
   local isFirst=true
   for ipLocal in ${arrIpLocal[@]}; do
      if $isFirst; then
         isFirst=false
      else
         filter=$filter' or'
      fi
      filter=$filter' dst host '$ipLocal
   done
   filter=$filter' )'

   # Obtaining possible listening addresses, such as listening at 0.0.0.0 and :::, means receiving incoming connections from any local network interface, and also includes the IP address bound by a valid network adapters.
   local effLsnIps=`echo ${arrIpLocal[@]} | sed 's/ /|/g'`'|0.0.0.0|:::'

   # Perform a inspection of all outside listening ports of this host.
   local lsnPorts=(`netstat -an | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $NF == "LISTEN" {print $4}' | sed 's/.*:\([0-9]*\)$/\1/g' | sort -u -n`)

   # If the current node is configured with a port forwarding strategy outside of the explicit listening port, it still needs to be blocked!
   local fwdPorts=(`iptables -t nat -L PREROUTING -n | awk '$1 == "DNAT" {print $0}' | sed 's/.*dpt:\([0-9]*\)\ .*/\1/g' | sort -u -n`)

   # Merge listening ports and forwarding ports
   local mergedPorts=( ${lsnPorts[@]} ${fwdPorts[@]} )

   # Resort the ports
   local allPorts=(`echo ${mergedPorts[@]} | sed 's/ /\n/g' | sort -u -n`)

   # Convert ports list to port ranges list
   local allPortRanges=(`ports_range "${allPorts[@]}"`)

   # Assemble the listening port ranges filter
   local rangeFilter=$(echo ${allPortRanges[@]} | sed 's/ /\n/g' | sed 's/^/or dst portrange /g' | tr '\n' ' ' | sed 's/^or//')
   rangeFilter="($rangeFilter)"

   # Reset the quintet file
   >quintet.txt

   # Added irrelevant feature: Obtain the mapping relationship between ports and processes
   netstat -anp | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $6 == "LISTEN" {print $4","$7}' | sed 's/.*:\([0-9]*,.*\)/\1/g' | sort -t, -u -k1n > map-ports-procs.txt

   # Begin to capture
   nohup $0 --run-caps --filter "$filter and $rangeFilter" &

   echo "[Info] Started $nProc tcpdump packet capture processes!"
}

#
# 6. Perform a single capture with one filter
#
run_cap() {

   if [ -z "$1" ]; then
      echo '[Warn] Pls provide the capture filter, such as dst port 80.'
      return
   fi

   # [Note] The traffic between K8s nodes, K8s pods and standalone containers has been fully released, should be excluded here.

   get_curr_node_ip

   # 1. Obtain the K8s nodes filter
   local nodesFilter=

   # Compress the node list into a subnet list
   local arrSubnets=(`python2 iprange.py --to-subnets ${nodes[@]}`)
   if [ ${#arrSubnets[@]} -ne 0 ]; then
      nodesFilter=$(echo ${arrSubnets[@]} | sed 's/ /\n/g' | sed 's/^/and not src net /g' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
   fi
   echo "[Info] The filter of cluster nodes: $nodesFilter."

   # 2. Obtain the K8s pod CIDR filter
   local podCidrFilter=
   if [ ! -z $podCidr ]; then
      podCidrFilter="and not src net $podCidr"
   fi
   echo "[Info] The filter of K8s pods CIDR: $podCidrFilter."

   # 3. Obtain the container subnet filter
   local cntrFilter=
   local arrSubCntr=($(docker network inspect `docker network ls --format '{{.Name}}'` 2>/dev/null | jq -r -c '.[].IPAM.Config|.[].Subnet'))
   if [ ${#arrSubCntr[@]} -ne 0 ]; then
      cntrFilter=$(echo ${arrSubCntr[@]} | sed 's/ /\n/g' | sed 's/^/and not src net /g' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
   fi
   echo "[Info] The filter of container network bridges: $cntrFilter."

   # [Note] The following is an explanation of the enabled parameters:
   # -l: Make stdout line buffered.  Useful if you want to see the data while capturing it.
   # -nn: Don't convert protocol and port numbers etc. to names either.
   # -q: Print less protocol information so output lines are shorter.
   local s="timeout $duration tcpdump -i any -lqnn '$1 $nodesFilter $podCidrFilter $cntrFilter'"

   echo "[Info] The traffic capturing statement: $s."

   eval $s 2>/dev/null | while IFS= read -r line; do
      local plc=`echo $line | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5} > ([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5}' | sed 's/\.[0-9]* > /,/g'`
      if [ `grep $plc quintet.txt | wc -l` -eq 0 ]; then
         echo $plc >> quintet.txt
      fi
   done
}

#
# 7. Comprehensive release of strategies between K8s nodes. Prerequisite: The node list configured in the current script is correct.
#
add_k8s_nodes_plcs() {

   if [ ${#nodes[@]} -eq 0 ]; then
      echo '[Warn] The nodes list is empty, pls use get_nodes() method to update the list first!'
      get_nodes
   fi

   get_curr_node_ip

   if [ -z "$currNodeIP" ]; then
      echo '[Warn] The data in the node list may not be accurate!'
      return
   fi

   echo '[Info] Adding K8s nodes policies ...'

   echo | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo '# Policies for K8s Nodes         #' | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo | tee -a block.sh


   # Convert node list to ip range list
   local arrIpRange=(`python2 iprange.py --to-ranges ${nodes[@]}`)

   # Add ip range list to accept policies
   for ipRange in ${arrIpRange[@]}; do
      echo "iptables -t raw -I PREROUTING -p tcp -m iprange --src-range $ipRange -j ACCEPT" | tee -a block.sh
   done

   echo '[Info] Done.'
}

#
# 8. Add an exception policies for K8s pods accessing open services on the current host.
#
add_k8s_pods_plcs() {

   if [ -z $podCidr ]; then
      return
   fi

   echo '[Info] Adding K8s pods policies ...'

   echo | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo '# Policies for K8s pods          #' | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo | tee -a block.sh

   echo "iptables -t raw -I PREROUTING -p tcp -s $podCidr -j ACCEPT # K8s pods policies" | tee -a block.sh

   echo '[Info] Done.'
}

#
# 9. Add an exception policies for standalone containers accessing open services on the current host.
#
add_cntr_plcs() {

   # Obtain the subnet list of all container network bridges
   local arrSubCntr=($(docker network inspect `docker network ls --format '{{.Name}}'` 2>/dev/null | jq -r -c '.[].IPAM.Config|.[].Subnet'))

   # Check if relevant strategies are involved
   if [ ${#arrSubCntr[@]} -eq 0 ]; then
      return
   fi

   echo '[Info] Adding container policies ...'

   echo | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo '# Policies for docker containers #' | tee -a block.sh
   echo '##################################' | tee -a block.sh
   echo | tee -a block.sh

   for subCntr in ${arrSubCntr[@]}; do
      echo "iptables -t raw -I PREROUTING -p tcp -s $subCntr -j ACCEPT # Standalone docker policies" | tee -a block.sh
   done

   echo '[Info] Done.'
}

#
# 10. Generate block scripts such as:
# iptables -t raw -A PREROUTING -p tcp -s 134.80.15.198 --dport 2181 -j ACCEPT
# iptables -t raw -A PREROUTING -p tcp -m tcp --dport 2181 -j DROP
#
gen_block_scripts() {

   if [ ! -f quintet.txt ]; then
      echo '[Warn] The IP quintuple file has not yet been created!'
      return
   fi

   echo '[Info] Generating network blocking script ...'

   echo '#####################################' | tee block.sh
   echo '# IPTABLES Blocking Scripts v240317 #' | tee -a block.sh
   echo '#####################################' | tee -a block.sh

   echo | tee -a block.sh
   echo '#!/bin/bash' | tee -a block.sh

   add_k8s_nodes_plcs

   add_k8s_pods_plcs

   add_cntr_plcs

   # General Blocking Scripts
   echo | tee -a block.sh
   echo '############################' | tee -a block.sh
   echo '# General Blocking Scripts #' | tee -a block.sh
   echo '############################' | tee -a block.sh

   echo | tee -a block.sh
   sort -t. -k8n quintet.txt | grep -v '^$' | while IFS= read -r line; do
      local srcAddr=`echo $line | awk -F',' '{print $1}'`
      local dstPort=`echo $line | awk -F',' '{print $2}' | awk -F'.' '{print $NF}'`
      local procName=`grep "^$dstPort," map-ports-procs.txt | head -1 | awk -F, '{print $2}'`
      echo "iptables -t raw -A PREROUTING -p tcp -s $srcAddr --dport $dstPort -j ACCEPT # "$procName | tee -a block.sh
   done

   # Perform a inspection of all addresses of all interfaces. Loopback network is not controlled by iptables and will be no longer considered!
   local arrIpLocal=(`get_host_ip_arr`)

   # Obtaining possible listening addresses, such as listening at 0.0.0.0 and :::, means receiving incoming connections from any local network interface, and also includes the IP address bound by a valid network adapters.
   local effLsnIps=`echo ${arrIpLocal[@]} | sed 's/ /|/g'`'|0.0.0.0|:::'

   # Perform a inspection of all outside listening ports of this host.
   local lsnPorts=(`netstat -an | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $NF == "LISTEN" {print $4}' | sed 's/.*:\([0-9]*\)$/\1/g' | sort -u -n`)

   # Adding multiple ports blocking policy
   local sLsnPorts=`echo ${lsnPorts[@]} | sed 's/ /,/g'`
   # -A PREROUTING -p tcp -m multiport --dports 3312,4443,50101,51012,51021,61588,6443,80,8001,8008,8443,9091,9093 -j DROP
   echo "iptables -t raw -A PREROUTING -p tcp -m multiport --dports $sLsnPorts -j DROP" | tee -a block.sh

   echo '[Done]'
}

#
# 11. Revoke all iptables blocking policies that have already been added
#
disable_block() {
   
   # Step1. Unlock all drop restrictions
   iptables -t raw -L PREROUTING --line-numbers --numeric | awk '$2 == "DROP" {print $1}' | sort -nr | while IFS= read -r line; do
      iptables -t raw -D PREROUTING $line
   done

   # Step2. Remove all accept policies
   iptables -t raw -L PREROUTING --line-numbers --numeric | awk '$2 == "ACCEPT" {print $1}' | sort -nr | while IFS= read -r line; do
      iptables -t raw -D PREROUTING $line
   done
}

#
# 12. Iptables persistence: After the next restart, the saved iptables policy will automatically take effect!
#
reserve_iptables() {

   if [ -z `rpm -qa iptables-services` ]; then
      echo '[Warn] You must install iptables-services first: yum -y install iptables-services!'
      return
   fi

   service iptables save

   if [ ! -f /etc/sysconfig/iptables ]; then
      echo '[Warn] Iptables not successfully backed up to /etc/sysconfig/iptables!'
      return
   fi

   systemctl enable iptables --now
}

#
# 13. Add exception policy, take effect immediately
#
add_except() {

   local srcHost=$1
   local dstPort=$2

   if [ -z $srcHost ] || [ -z $dstPort ]; then
      echo '[Warn] You at least provide source IP address and destination port number!'
      return
   fi

   local procName=`grep "^$dstPort," map-ports-procs.txt | head -1 | awk -F, '{print $2}'`

   # Add exception policy to block.sh
   local plc="iptables -t raw -I PREROUTING -p tcp -s $srcHost --dport $dstPort -j ACCEPT # $procName"
   echo $plc >> block.sh
   
   eval "$plc"
}

#
# 14. Load exception policies from configuration file
#
add_cfg_excepts() {
   echo 'Not implemented'
}

#
# 15. Review the traffic after blocking, observe the blocking effect, and manually review whether some traffic should be released.
#
traff_review() {

   
   get_curr_node_ip
}

#
# Dispatch capturing jobs for general nodes
#
# dispatch_caps() {
#    echo 'Not Implemented Feature'
# }

#
# Dispatch capturing jobs for all K8s nodes
#
dispatch_caps() {

   # Refresh nodes list
   get_nodes

   # Convert array to csv
   local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

   # Obtain the pods CIDR
   get_pod_cidr

   # Obtain the file name of current shell
   local selfName=$(basename $0)

   # Obtain the file name of current shell without extension name
   local noExt=$(echo $selfName | sed 's/^\(.*\)\.[0-9A-Za-z]*$/\1/g')

   # Assemble the log file name
   local logFileName=$noExt'.log'

   # Work Folder
   local workDir=$(pwd)

   ansible all -i "$nodesList" -m shell -a "mkdir -p $workDir" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=$0 dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=ipaddress-1.0.23-py2.py3-none-any.whl dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=iprange.py dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "cd $workDir; chmod +x $selfName; nohup ./$selfName --run-host-caps 1>>$logFileName 2>>$logFileName &" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "echo -n 'Capturing processes num: '; ps -ef | grep tcpdump | grep -vE 'grep|timeout' | wc -l" -f ${#nodes[@]} -o
}

qry_cap_proc_num() {

   # Refresh nodes list
   get_nodes

   # Convert array to csv
   local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

   ansible all -i "$nodesList" -m shell -a "echo -n 'Capturing processes num: '; ps -ef | grep tcpdump | grep -vE 'grep|timeout' | wc -l" -f ${#nodes[@]} -o
}

#
# Dispatch tasks of blocking scripts generation
#
dispatch_gen_tasks() {

   # Refresh nodes list
   get_nodes

   # Convert array to csv
   local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

   # Obtain the pods CIDR
   get_pod_cidr

   # Obtain the file name of current shell
   local selfName=$(basename $0)

   # Work Folder
   local workDir=$(pwd)

   ansible all -i "$nodesList" -m shell -a "mkdir -p $workDir" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=$0 dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "cd $workDir; chmod +x $selfName; ./$selfName --gen-block-scripts" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "cd $workDir; ls -ltr block.sh" -f ${#nodes[@]} -o
}

#
# Dispatch iptables block jobs
#
dispatch_blocks() {

   # Refresh nodes list
   get_nodes

   # Convert array to csv
   local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

   # Obtain the pods CIDR
   get_pod_cidr

   # Obtain the file name of current shell
   local selfName=$(basename $0)

   # Work Folder
   local workDir=$(pwd)

   ansible all -i "$nodesList" -m shell -a "mkdir -p $workDir" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=$0 dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "cd $workDir; sh block.sh" -f ${#nodes[@]}
}

#
# Batchly rollback block operations.
#
dispatch_rollbacks() {
   # Refresh nodes list
   get_nodes

   # Convert array to csv
   local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

   # Obtain the pods CIDR
   get_pod_cidr

   # Obtain the file name of current shell
   local selfName=$(basename $0)

   # Work Folder
   local workDir=$(pwd)

   ansible all -i "$nodesList" -m shell -a "mkdir -p $workDir" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m copy -a "src=$0 dest=$workDir/" -f ${#nodes[@]}

   ansible all -i "$nodesList" -m shell -a "cd $workDir; chmod +x $selfName; ./$selfName --disable-block" -f ${#nodes[@]}
}

#########################################
# Mappings between params and methods   #
#########################################

if [[ "${*}" =~ "--duration" ]]; then

   n=`echo ${*} | sed 's/ /\n/g' | grep -A 1 "\-\-duration" | tail -1`
   if [[ ! "$n" =~ ^[0-9]+$ ]]; then
      echo '[Warn] Pls input a valid number!'
      exit 1
   fi

   duration=$n

   perl -p -i -e "s/^duration=.*/duration=$duration/g" $0
fi

if [[ "${*}" =~ "--get-nodes" ]]; then
   get_nodes
   echo "[Info] The nodes are as the following:"
   echo ${nodes[@]} | sed 's/ /\n/g' | sed 's/^/   /g'
   exit 0
fi

if [[ "${*}" =~ "--get-curr-node-ip" ]]; then
   get_curr_node_ip
   echo "[Info] The IP of current node: $currNodeIP."
   exit 0
fi

if [[ "${*}" =~ "--get-host-ip-arr" ]]; then
   arrIpLocal=(`get_host_ip_arr`)
   echo "[Info] The local IPs are as the following:"
   echo ${arrIpLocal[@]} | sed 's/ /\n/g' | sed 's/^/   /g'
   exit 0
fi

if [[ "${*}" =~ "--get-pod-cidr" ]]; then
   get_pod_cidr
   echo $podCidr
   exit 0
fi

if [[ "${*}" =~ "--run-caps" ]] && [[ "${*}" =~ "--filter" ]]; then
   filter=`echo "${*}" | awk '{for(i=3; i<=NF; i++) {printf " %s", $i}}'`
   run_cap "$filter"
   exit 0
fi

if [[ "${*}" =~ "--add-k8s-nodes-plcs" ]]; then
   add_k8s_nodes_plcs
   exit 0
fi

if [[ "${*}" =~ "--add-k8s-pods-plcs" ]]; then
   add_k8s_pods_plcs
   exit 0
fi

if [[ "${*}" =~ "--add-cntr-plcs" ]]; then
   add_cntr_plcs
   exit 0
fi

if [[ "${*}" =~ "--reserve-iptables" ]]; then
   reserve_iptables
   exit 0
fi

if [[ "${*}" =~ "--add-except" ]]; then
   add_except
   exit 0
fi

if [[ "${*}" =~ "--add-cfg-excepts" ]]; then
   add_cfg_excepts
   exit 0
fi

#
# Manual maintenance
#
# for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
#    echo $node
#    timeout 3 scp -rp iptables-block.sh $node:/root/
#    timeout 3 ssh $node "nohup ./iptables-block.sh --run-host-caps 1>/dev/null 2>/dev/null &"
# done

# for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
#    echo $node
#    timeout 2 ssh $node "ps -ef | grep tcpdump | grep -v grep | wc -l"
# done

# for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
#    echo $node
#    timeout 2 ssh $node "which tcpdump"
# done

# 1121  <------ 134.80.209.11
# 22 4A
# 限制目的IP

#
# 16. Usage
#
usage() {
   echo 'Network Strategy Convergence and Blocking Tools [240520]'
   echo '[Usage]'

   local selfName=$(basename $0)
   
   for opt in ${!mapParaSpec[@]}; do
      echo "   ./$selfName $opt   ${mapParaSpec[$opt]}"
   done
}

#
# Maps between shell options and functions
#
declare -A mapParaFunc=(
   ["--run-host-caps"]="run_host_caps"
   ["--gen-block-scripts"]="gen_block_scripts"
   ["--disable-block"]="disable_block"
   ["--dispatch-caps"]="dispatch_caps"
   ["--qry-cap-proc-num"]="qry_cap_proc_num"
   ["--dispatch-gen-tasks"]="dispatch_gen_tasks"
   ["--dispatch-blocks"]="dispatch_blocks"
   ["--dispatch-rollbacks"]="dispatch_rollbacks"
   ["--usage"]="usage"
   ["--help"]="usage"
   ["--manual"]="usage"
)

#
# Maps between shell options and specifications
#
declare -A mapParaSpec=(
   ["--run-host-caps"]="Start traffic capture and analysis on the current node."
   ["--gen-block-scripts"]="Generate block scripts to block.sh."
   ["--disable-block"]="Unlock all restrictions, rollback the blocking operations."
   ["--dispatch-caps"]="Dispatch capturing jobs for all K8s nodes."
   ["--qry-cap-proc-num"]="Query the capturing processes number."
   ["--dispatch-gen-tasks"]="Dispatch tasks of blocking scripts generation."
   ["--dispatch-blocks"]="Dispatch iptables block jobs."
   ["--dispatch-rollbacks"]="Batchly rollback block operations."
   ["--usage"]="Simplified operation manual."
   ["--help"]="Simplified operation manual."
   ["--manual"]="Simplified operation manual."
)

if [ ! -z "$1" ] && [[ "${!mapParaFunc[@]}" =~ "$1" ]]; then
   eval ${mapParaFunc["$1"]} $2 $3 $4 $5 $6 $7 $8 $9
   exit 0
fi
