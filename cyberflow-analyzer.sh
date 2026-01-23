###################################
# CYBERFLOW-Analyzer     v251221  #
# Exposures,Capture,Defender      #
###################################

#!/bin/bash

# [Note] Working principles: Analyze Host Exposures → Capture Packets → Generate iptables blocking execution plan
# [Improvement]
#  [1] Use ipset as a substitution of iprange, multiport, ..., to improve performance
#  [2] Fully compatible with TCP/UDP protocol and IPv4/6 dual stack
#  [3] Unify the iptables port forwarding strategies and port listenings as exposures
#  [4] Analyze the exposed surface first, and then capture packets, that is, carry out targeted traffic capture. More accurate inbound strategy analysis.
#  [5] In this release, the tshark mode has been deprecated, and tcpdump has been reinstated as the replacement. Although tshark can provide richer analysis of packet content (such as supporting JSON format output), its capability to directly decode data has significantly diminished in practical scenarios. Currently, most traffic is encrypted using SSL, rendering tshark ineffective for parsing. Furthermore, tshark has notable limitations in handling complex, lengthy filters; its performance severely degrades and may even fail entirely when the number of filtering conditions increases.
#  [6] In this version, due to the introduction of iptables exposed surface acquisition, K8s API permissions and kubectl are no longer mandatory, which leads to differences in processing methods between master and worker nodes in the K8s cluster, indirectly increasing the complexity of the design.

#########################################
# Bugs, Defects and Other Problems      #
#########################################

# [1] There is a case where port forwarding is configured on iptables, but the listening port on the current node cannot be seen through netstat. [Done]
# [2] Analyzing processes of each listening port. [Done]
# [3] When the container on the current node accesses open services on the current node, due to the dynamic nature of the container IP, the address segments of the container network, such as the bip address segment and all address segments under the Docker network, such as the kube apiserver service port, should be released. This function is not universal, therefore it is not included as a regular function. [Done]
# [4] The intercepted request can be correctly identified and the connection failure caused by security protection can be found in time.
# [5] Iptables automatically takes effect after the host is restarted.
# [6] Add manually backup functions.
# [7] udp is not properly handled! [Done]
# [8] multiport optimize [Done]
# [9] The local link addresses 127.0.0.0/8 and fe80::/10 are both loopback address networks, and traffic passing through these addresses should be filtered. [Done]
# [10] Interpretability of IP quintuple data;
# [11] iptables -t raw -I PREROUTING -p tcp -s 2001:db8:abc1::/64 -j ACCEPT # Standalone docker policies 
# [12] The blocking of IPv6 addresses requires the use of the ip6tables command. [Done]
# [13] The function of automatically revoking blockage within 5 minutes.
# [14] Add comment to all generated strategies. [Done]
# [15] netstat -anltp needs to be replaced with ss -nltp to improve the query efficiency and accuracy of the listening ports. [Done]
# [16] External IP is based on existing generation logic, with nodeport port listening and nodeport iptables (newer k8s version). [Done]
# [17] Outbound packet capture and summarization. [Done]
# [18] Auxiliary strategy verification function.
# [19] Generation of switch deployment strategy. [Done]
# [20] Integrate CMDB strategy translation.
# [21] Analyzing invalid traffic, mainly including RST packets, usually causes a decrease in host connection rate.
# [22] A specialized processing mode for FTP protocol, with the target end being a dynamically open listening port.
# [23] Large scale cluster with multiple nodes for unified scheduling.
# [24] Remote batch push
# [25] 允许在历史连接摘要表的基础上进行策略更新，允许多次短时数据包捕获，同时允许对长期不活跃的连接策略予以回收。
# [26] 在生成的iptables放通策略脚本中，添加目的端口策略描述，提升可读性；
# [27] 在生成策略配置文件时，针对k8s核心组件的端口策略需特殊处理，如etcd端口策略、apiserver策略、vxlan端口捕获的数据包不能足以覆盖所有客户端；
# [28] 兜底方案：因数据包分析和分析不全面导致疏漏的连接策略，在封堵后出现无法正常访问的情况，应实时流量观察，先放通再列入pending审查清单；
# [29] 特权连接配置：增加 .legacy-connections，以满足维护需要。
# [30] 蜜罐支持，对于一些常见暴露面如ssh，对于没有特权的IP，可以NAT到蜜罐容器

#########################################
# Verifications                         #
#########################################

# Sort by age to obtain the oldest pods
# kubectl get pods --all-namespaces --no-headers --sort-by={.metadata.creationTimestamp} | head -5

# Patch the deploy
# kubectl patch deploy beegrid-chat-service -n beegrid --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/ports", "value": [{"containerPort": 7007, "hostPort": 57007, "protocol": "TCP"}]}]'
# kubectl get pod -n beegrid -o wide | grep '^beegrid-chat-service'


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

# [Note] In some operating systems such as the debian ecosystem, which cannot obtain alias configuration data. Therefore, alias requires special handling

if [ -z "$(which tcpdump 2>/dev/null)" ] && [ -z "$(alias tcpdump 2>/dev/null)" ]; then
   echo '[Warn] tcpdump is not installed yet.'
   exit -1
fi

if [ -z "$(which lsof 2>/dev/null)" ] && [ -z "$(alias lsof 2>/dev/null)" ]; then
   echo '[Warn] lsof is not installed yet.'
   exit -1
fi

if [ -z "$(which python2 2>/dev/null)" ] && [ -z "$(alias python2 2>/dev/null)" ]; then
   echo '[Warn] python2 is not installed yet.'
   exit -1
fi

if [ -z "$(which pip2 2>/dev/null)" ] && [ -z "$(alias pip2 2>/dev/null)" ]; then
   echo '[Warn] python2-pip is not installed yet.'
   exit -1
fi

if [ -z "$(which bc 2>/dev/null)" ]; then
   echo '[Warn] bc is not installed yet.'
   exit -1
fi

pip2 show ipaddress -q 2>/dev/null
if [ $? -ne 0 ]; then
   pip2 install ipaddress-1.0.23-py2.py3-none-any.whl -q 2>/dev/null
   exit -1
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

   # ipvs
   '^kube-ipvs'

   'vmnet'

   '^dummy'
)

#
# 2. Continuous packet capture duration in seconds
#
PACKETS_CAPTURE_DURATION=60

#
# 3. All nodes' IP configurations. This configuration is automatically managed by scripts, please do not manually modify it! The following is a sample configuration, which will be automatically updated when subsequent functions are executed. The followings are demo node IP addresses.
#
nodes=(
)

#
# 4. Current Node's IP. When a backup task is assigned to a node, the IP address of the node can be determined based on the intersection of the IP addresses of the K8s node and all network IP addresses of the current node.
#
currNodeIP=

#
# 5. The CIDR of K8s pods
#
podCidr=

#
# 6. The Work Folder
#
WORKING_DIRECTORY=$(dirname $(realpath $0))
if [ $? -ne 0 ]; then
   WORKING_DIRECTORY=$(pwd)
fi

#
# 7. Max Jobs of concurrent process
#
MAX_JOBS=36

LEGACY_SSHD_ORIGINAL_PORT=22

#
# 8. The system service unit file path
#
SYSTEM_SERVICE_UNIT_FILE_PATH=

#
# [Note] A list of Container Network Interface (CNI) plugins. Simply put, its main function is to provide a collection of common options for networking solutions for Kubernetes clusters.
#
CNI_TYPES=(
   Calico
   Flannel
   Cilium
   Weave
   Antrea
   Canal
   Kube-router
   OVN-Kubernetes
)

#
# [Note] The subnets on Loopback Interface. The system service can listen at address 127.0.0.0/8, so that the service is only available locally and will not be exposed to external networks, improving security. Use ip a show lo to get the subnets addresses. Not strict mode.
#
LOOPBACK_SUBNETS_IPV4=127.0.0.0/8
LOOPBACK_SUBNETS_IPV6=::1/128

PREFER_IPV6=false

IPTABLES_COMMENT='Unified Access Control'

#########################################
# Load Configuration Data               #
#########################################

load_external_interfaces_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.external-interfaces ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-external-interfaces
   fi

   EXTERNAL_INTERFACES=($(cat ${WORKING_DIRECTORY}/.external-interfaces 2>/dev/null))

   if [ ${#EXTERNAL_INTERFACES[@]} -eq 0 ]; then
      EXTERNAL_INTERFACES=('any')
   fi
}

load_external_ip_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.external-ip ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-external-ip-addresses
   fi

   EXTERNAL_IP_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.external-ip 2>/dev/null))
   EXTERNAL_IPV4_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.external-ipv4 2>/dev/null))
   EXTERNAL_IPV6_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.external-ipv6 2>/dev/null))
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

load_cluster_cidr_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.cluster-cidr ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-cluster-cidr
   fi

   CLUSTER_CIDR=($(cat ${WORKING_DIRECTORY}/.cluster-cidr 2>/dev/null))
   CLUSTER_CIDR_IPV4=($(cat ${WORKING_DIRECTORY}/.cluster-cidr-ipv4 2>/dev/null))
   CLUSTER_CIDR_IPV6=($(cat ${WORKING_DIRECTORY}/.cluster-cidr-ipv6 2>/dev/null))
}

load_service_cidr_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.service-cidr ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --dump-service-cidr-from-service-list
   fi

   SERVICE_CIDR=($(cat ${WORKING_DIRECTORY}/.service-cidr 2>/dev/null))
   SERVICE_CIDR_IPV4=($(cat ${WORKING_DIRECTORY}/.service-cidr-ipv4 2>/dev/null))
   SERVICE_CIDR_IPV6=($(cat ${WORKING_DIRECTORY}/.service-cidr-ipv6 2>/dev/null))
}

load_kvm_subnet_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.kvm-networks ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-kvm-subnet-addresses
   fi

   KVM_SUBNET_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.kvm-networks 2>/dev/null))
   KVM_SUBNET_ADDRESSES_IPV4=($(cat ${WORKING_DIRECTORY}/.kvm-networks-ipv4 2>/dev/null))
   KVM_SUBNET_ADDRESSES_IPV6=($(cat ${WORKING_DIRECTORY}/.kvm-networks-ipv6 2>/dev/null))
}

load_vmware_subnet_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.vmware-networks ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-vmware-subnet-addresses
   fi

   VMWARE_SUBNET_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.vmware-networks 2>/dev/null))
   VMWARE_SUBNET_ADDRESSES_IPV4=($(cat ${WORKING_DIRECTORY}/.vmware-networks-ipv4 2>/dev/null))
   VMWARE_SUBNET_ADDRESSES_IPV6=($(cat ${WORKING_DIRECTORY}/.vmware-networks-ipv6 2>/dev/null))
}

load_k8s_nodes_ip_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.k8s-nodes ]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-k8s-nodes-ip-addresses
   fi

   K8S_NODES_IP_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.k8s-nodes 2>/dev/null))
   K8S_NODES_IPV4_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.k8s-nodes-ipv4 2>/dev/null))
   K8S_NODES_IPV6_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.k8s-nodes-ipv6 2>/dev/null))
   K8S_NODES_SUBNETS=($(cat ${WORKING_DIRECTORY}/.k8s-nodes-subnets 2>/dev/null))
   K8S_NODES_IPV4_SUBNETS=($(cat ${WORKING_DIRECTORY}/.k8s-nodes-ipv4-subnets 2>/dev/null))
   K8S_NODES_IPV6_SUBNETS=($(cat ${WORKING_DIRECTORY}/.k8s-nodes-ipv6-subnets 2>/dev/null))
}

load_system_service_unit_file_path() {

   SYSTEM_SERVICE_UNIT_FILE_PATH=$(pkg-config systemd --variable=systemdsystemunitdir)

   if [ -z "${SYSTEM_SERVICE_UNIT_FILE_PATH}" ]; then
      for i in $(systemctl show --property=UnitPath --no-page | sed 's#UnitPath=##g' | tr ' ' '\n'); do
         if [[ ! "$i" =~ "/run" ]] && [ -d "$i" ]; then
            SYSTEM_SERVICE_UNIT_FILE_PATH="$i"
         fi
      done
   fi

   if [ -z "${SYSTEM_SERVICE_UNIT_FILE_PATH}" ]; then
      SYSTEM_SERVICE_UNIT_FILE_PATH=$(dirname $(systemctl show sysinit.target --property=FragmentPath | sed 's#FragmentPath=##g'))
   fi

   echo "[Info] The system service unit file path: ${SYSTEM_SERVICE_UNIT_FILE_PATH}"
}

load_vxlan_listen_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.vxlan-listen-addresses ] || [[ "${*}" =~ "--no-cache" ]]; then
      ${WORKING_DIRECTORY}/network-utilities.sh --get-vxlan-listen-addresses
   fi

   VXLAN_IPV4_LISTEN_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.vxlan-ipv4-listen-addresses 2>/dev/null))
   VXLAN_IPV6_LISTEN_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.vxlan-ipv6-listen-addresses 2>/dev/null))
   VXLAN_LISTEN_ADDRESSES=($(cat ${WORKING_DIRECTORY}/.vxlan-listen-addresses 2>/dev/null))
}


#########################################
# Common Utilities                      #
#########################################

#
# [Note] On the basis of the original grouping and merging function, add functions such as deduplication, sorting, and quantity limitation. Group according to the first column, with members in each group in the second column, separated by commas, with a maximum of 15 members in each group.
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
# [Note] Group according to the first column, with members in each group in the second column, separated by commas. There is no upper limit to the number of members in each group.
#
group_by_1st_column_no_limit() {
   awk '
   BEGIN {
     OFS = " "
   }
   {
      if (!seen[$1,$2]++) {
         arr[$1] = (arr[$1] == "" ? $2 : arr[$1] "," $2)
      }
   } 
   END {
      for (key in arr) {
         print key, arr[key]
      }
   }'
}

# group_by_1st_column_no_limit() {
#    awk '
#    {
#       # De duplication: Each second column value corresponding to the first column is only recorded once
#       if (!seen[$1","$2]++) {
#          # Record values and mark the need for sorting
#          value_count[$1]++
#          values[$1][value_count[$1]] = $2
#       }
#    }
#    END {
#       # Traverse all groups
#       for (key in values) {
#          count = 0
#          group_index = 1
#          result = ""
         
#          # Sort values numerically
#          n = value_count[key]
#          for (i = 1; i <= n; i++) {
#             temp_arr[i] = values[key][i]
#          }
#          asort(temp_arr, sorted_values)
         
#          # Build group output
#          for (i = 1; i <= n; i++) {
#             if (count++ > 0) result = result ","
#             result = result sorted_values[i]
#          }
         
#          if (count > 0) {
#             print key " " result
#          }
#       }
#    }'
# }

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
# [Note] The abstract function of parallel processing includes three parameters: the name of the processing function, the file to be processed, and the number of records processed by a single process
#
abstract_concurrent_process() {

   local processorName=$1
   local filePath=$2
   local singleProcessRecordsNumber=$3
   local totalRecordsNumber=
   local temporaryFilePath="$filePath.tmp"

   if [ -z "$processorName" ] || [ -z "$filePath" ] || [ ! -f "$filePath" ]; then
      echo '[Warn] You should provide the name of the processing function and the full path of the file to be processed.'
      return
   fi

   # The default number of records processed by a single process
   if [ -z "$singleProcessRecordsNumber" ]; then
      singleProcessRecordsNumber=50
   fi

   totalRecordsNumber=$(wc -l $filePath | awk '{print $1}')

   >$temporaryFilePath

   local maxJobs=$(echo "scale=0; $totalRecordsNumber / $singleProcessRecordsNumber" | bc)
   local jobCount=0

   local i=0
   while [ $i -le $maxJobs ]; do

      local beginLineNo=$(echo "$i * $singleProcessRecordsNumber + 1" | bc)
      local endLineNo=$(echo "$i * $singleProcessRecordsNumber + $singleProcessRecordsNumber" | bc)
      ($processorName "$filePath" "$beginLineNo" "$endLineNo") &
      ((jobCount++))

      # If the number of running jobs reaches the limit, then wait.
      if [[ $jobCount -ge $maxJobs ]]; then
         wait           # Waiting for all current background tasks to end
         jobCount=0     # Reset counter
      fi

      i=$(expr $i + 1)
   done

   wait                 # Waiting for the end of the last batch of backend tasks

   echo "[Info] Processing $filePath complete."
}

#
# [Note] Write the temporary file back to the original file
#
writeback_temporary_file() {
   
   local originalFilePath=$1
   local temporaryFilePath="$originalFilePath.tmp"

   if [ -z "$originalFilePath" ]; then
      echo '[Warn] The current method relies on one parameter: the original file path.'
      exit -1
   fi

   if [ ! -f $temporaryFilePath ]; then
      echo "[Warn] The temporary file $temporaryFilePath does not exist."
      return
   fi
   
   /usr/bin/mv -f $temporaryFilePath $originalFilePath
   echo "[Info] Writeback $temporaryFilePath → $originalFilePath"
}

#
# [Note] Push file to node
#
deliver() {

   local localFile=$1
   local sshServer=$2
   local sshPort=$3
   local remoteFolder=$(dirname $(realpath $localFile))

   ssh -p $sshPort $sshServer "mkdir -p $remoteFolder"

   scp -o ConnectTimeout=5 -P $sshPort -rp $localFile $sshServer:$remoteFolder 2>/dev/null
}

#
# [Note] Push specified file to all K8s nodes
#
batch_remote_deliver() {

   local filePath=$1
   local jobCount=0

   if [ -z "$filePath" ] || [ ! -f "$filePath" ]; then
      echo '[Warn] Please provide a valid path of the file to be delivered.'
      exit -1
   fi

   load_k8s_nodes_ip_addresses_from_file

   for i in ${K8S_NODES_IP_ADDRESSES[@]}; do
      (deliver $filePath $i ${LEGACY_SSHD_ORIGINAL_PORT}) &
      ((jobCount++))

      if [[ $jobCount -ge ${MAX_JOBS} ]]; then
         wait          # Waiting for all current background tasks to end
         jobCount=0    # Reset counter
      fi
   done

   wait

   echo "[Complete]"
}

#
# [Note] Execute programs on all K8s nodes
#
batch_remote_execute() {

   local commands="${*}"
   local jobCount=0

   if [ -z "$filePath" ] || [ ! -f "$filePath" ]; then
      echo '[Warn] Please provide a valid path of the file to be delivered.'
      exit -1
   fi

   load_k8s_nodes_ip_addresses_from_file

   for i in ${K8S_NODES_IP_ADDRESSES[@]}; do
      ("$commands") &
      ((jobCount++))

      if [[ $jobCount -ge ${MAX_JOBS} ]]; then
         wait          # Waiting for all current background tasks to end
         jobCount=0    # Reset counter
      fi
   done

   wait

   echo "[Complete]"
}

#########################################
# Common Routines / Functions area      #
#########################################

#
# [Note] A general method for setting list type parameters, used to set the array parameter values in the current shell script. The first parameter is the array name, such as nodes for nodes=(), the second parameter is the value, such as ${nodes[@]}
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
# [Note] Check if the subnet parameter contains external IP of current node, and this situation will be considered as exposures. Prerequisites: the EXTERNAL_IPV*_ADDRESSES variables must be loaded 
#
check_if_subnet_in_exposure() {

   local subnet=$1
   local ipFamily=
   local externalIP=
   local result=

   if [ -z "$subnet" ]; then
      echo '[Warn] Please provide subnet address.'
      exit -1
   fi

   # Shortcut check for wildcard subnet IP addresses, belonging to the exposure scope
   # Matching rules: 0.0.0.0 is equivalent to 0.0.0.0/0, [::] is equivalent to ::/0, * is equivalent to both 0.0.0.0/0 and ::/0
   if [[ "$subnet" =~ "0.0.0.0" ]] || [ "$subnet" == "::/0" ] || [ "$subnet" == "[::]" ] || [ "$subnet" == "*" ]; then
      echo 'true'
      return
   fi

   # Shortcut check for loopback subnet IP addresses, not belonging to the exposure scope
   # Matching rules: 127.0.0.1 is equivalent to 127.0.0.1/32, [::1] is equivalent to ::1/128
   if [[ "$subnet" =~ "127.0.0.1" ]] || [ "$subnet" == "[::1]" ]; then
      echo 'false'
      return
   fi

   # Remove the [] bracket
   subnet=$(echo "$subnet" | sed 's/^\[\(.*\)\]$/\1/')

   ipFamily=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --get-ip-family "$subnet")

   if [ "$ipFamily" == "IPv4" ]; then

      for externalIP in ${EXTERNAL_IPV4_ADDRESSES[@]}; do

         # Convert IP address format to subnet IP address format
         if [[ ! "$externalIP" =~ "/" ]]; then
            externalIP="$externalIP/32"
         fi

         result=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --is-subnet "$externalIP" "$subnet" | tr '[:upper:]' '[:lower:]')

         if $result; then
            echo 'true'
            return
         fi
      done

   elif [ "$ipFamily" == "IPv6" ]; then

      for externalIP in ${EXTERNAL_IPV6_ADDRESSES[@]}; do

         # Convert IP address format to subnet IP address format
         if [[ ! "$externalIP" =~ "/" ]]; then
            externalIP="$externalIP/128"
         fi

         result=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --is-subnet "$externalIP" "$subnet" | tr '[:upper:]' '[:lower:]')

         if $result; then
            echo 'true'
            return
         fi
      done
   fi

   echo 'false'
}

#
# [Note] This method is used to directly obtain the annotation information of jump linked lists in DNAT strategies, and is commonly used for link tracing in K8s services.
#
get_comments_of_dnat_exposure() {
   
   local linkName=$1

   if [ -z "$linkName" ]; then
      return
   fi

   if [[ "$linkName" =~ "KUBE-SVC" ]] || [[ "$linkName" =~ "KUBE-SEP" ]]; then
      iptables -t nat -S $linkName -w 2>/dev/null | grep -v -w '\-N' | grep -v 'MARK' | head -1 | sed 's#.*--comment "\([^"]*\)".*#\1#g'
   fi
}

#
# [Note] Single process processing of iptables port forwarding policies dump file specified by parameter 1. The starting and ending lines of the next two parameters indicate the scope of the processed file content.
#
process_dnat_exposures() {

   local filePath=$1
   local beginLineNo=$2
   local endLineNo=$3
   local IFS=$'\n'
   local temporaryFilePath="$filePath.tmp"
   local k=

   if [ -z "$filePath" ] || [ -z "$beginLineNo" ] || [ -z "$endLineNo" ]; then
      echo '[Warn] This function need 3 parameters: the iptables strategies file path, the begin line number and the end line number of this file.'
      exit -1
   fi

   for k in $(sed -n "$beginLineNo,$endLineNo"p $filePath); do
      
      local source=$(echo "$k" | awk -F';' '{print $1}')
      local destination=$(echo "$k" | awk -F';' '{print $2}')
      local ports=$(echo "$k" | awk -F';' '{print $3}')
      local to=$(echo "$k" | awk -F';' '{print $4}')

      # Filter: The policies jump to *MARK* links will be ignored
      if [[ "$to" =~ "MARK" ]]; then
         continue
      fi

      # Pending Filter: The function of checking if the source subnet address belongs to private subnet is not implemented. The definition of private subnets is relatively difficult, such as the KVM subnet, VMware subnet, K8s pod CIDR, Docker bridge, etc. on the current host, which can theoretically be defined as private subnets.

      # Filter: Check if destination address contains external IP
      local result=$(check_if_subnet_in_exposure "$destination")
      if ! $result; then
         continue
      fi

      # [Note] Convert obscure KUBE-SVC* and KUBE-SEP* into annotations
      to=$(get_comments_of_dnat_exposure "$to")

      # CIDR Suffix Omission: In IPv4, /32 means that this IP address has no network part and the entire 32 bits are used for host identification. Both represent precise individual IP addresses, so they are omitted to ensure consistency with the TCP/UDP listening table.
      if [[ "$source" =~ "/32" ]] || [[ "$source" =~ "/128" ]]; then
         source=$(echo "$source" | sed 's#/[0-9]*##g')
      fi

      if [[ "$destination" =~ "/32" ]] || [[ "$destination" =~ "/128" ]]; then
         destination=$(echo "$destination" | sed 's#/[0-9]*##g')
      fi

      # Split the multiports strategies of iptables into independent port strategies
      local port=
      for port in $(echo "$ports" | tr ',' '\n'); do
         echo "$source;$destination;$port;$to" >> $temporaryFilePath
      done
   done
}

#
# [Note] This method is used for dump iptables strategies, such as tcp4, udp4, tcp6 and udp6.
# Add the following strategies to verify:
#   ip6tables -t nat -A PREROUTING -s 2001:db8::1/128 -d 2001:db8::2/128 -p tcp -m tcp --dport 44444 -m comment --comment "Unusable Strategies" -j DNAT --to-destination [2001:db8::3]:44444
#   ip6tables -t nat -A PREROUTING -s 2001:db8::1/128 -d 2001:db8::2/128 -p udp -m udp --dport 44444 -m comment --comment "Unusable Strategies" -j DNAT --to-destination [2001:db8::3]:44444
#   echo '[{"bond0":["2001:db8::1/128","2001:db8::2/128","2001:db8::3/128"]}]' | jq -r . | tee .secondary-addresses; ./network-utilities.sh --add-secondary-addresses
#   nc -6 -lkvt -w 5 2001:db8::2 44444
#
dump_dnat_strategy_tables() {

   load_external_ip_addresses_from_file

   # [1] Generate TCP4/UDP4 DNAT exposures file
   if [ ${#EXTERNAL_IPV4_ADDRESSES[@]} -ne 0 ]; then
      # Filter the port forwarding strategy based on the --dport[s] keyword and save it as raw data to a file
      # We extracted several key attributes from the DNAT policies: The source client, the destination server, the destination ports and forwarded to anywhere
      iptables -t nat -S -w | grep '\--dport' | grep '\-p tcp' | awk '{
         source = "0.0.0.0/0"; destination = "0.0.0.0/0"; dports = "N/A"; to = "N/A"
         for(i=1; i<=NF; i++) {
            if ($i == "-s" || $i == "--src-range") { source = $(i+1) }
            else if ($i == "-d") { destination = $(i+1) }
            else if ($i == "--dport" || $i == "--dports") { dports = $(i+1) }
            else if ($i == "--to-destination" || $i == "-j") { to = $(i+1) }
         }
         print source";"destination";"dports";"to
      }' > ${WORKING_DIRECTORY}/.tcp4-dnat-exposures

      echo "[Info] $(wc -l ${WORKING_DIRECTORY}/.tcp4-dnat-exposures | awk '{print $1}') records have been saved in ${WORKING_DIRECTORY}/.tcp4-dnat-exposures"

      iptables -t nat -S -w | grep '\--dport' | grep '\-p udp' | awk '{
         source = "0.0.0.0/0"; destination = "0.0.0.0/0"; dports = "N/A"; to = "N/A"
         for(i=1; i<=NF; i++) {
            if ($i == "-s" || $i == "--src-range") { source = $(i+1) }
            else if ($i == "-d") { destination = $(i+1) }
            else if ($i == "--dport" || $i == "--dports") { dports = $(i+1) }
            else if ($i == "--to-destination" || $i == "-j") { to = $(i+1) }
         }
         print source";"destination";"dports";"to
      }' > ${WORKING_DIRECTORY}/.udp4-dnat-exposures

      echo "[Info] $(wc -l ${WORKING_DIRECTORY}/.udp4-dnat-exposures | awk '{print $1}') records have been saved in ${WORKING_DIRECTORY}/.udp4-dnat-exposures"
   fi

   # [2] Generate TCP6/UDP6 DNAT exposures file
   if [ ${#EXTERNAL_IPV6_ADDRESSES[@]} -ne 0 ]; then

      ip6tables -t nat -S -w | grep '\--dport' | grep '\-p tcp' | awk '{
         source = "::/0"; destination = "::/0"; dports = "N/A"; to = "N/A"
         for(i=1; i<=NF; i++) {
            if ($i == "-s" || $i == "--src-range") { source = $(i+1) }
            else if ($i == "-d") { destination = $(i+1) }
            else if ($i == "--dport" || $i == "--dports") { dports = $(i+1) }
            else if ($i == "--to-destination" || $i == "-j") { to = $(i+1) }
         }
         print source";"destination";"dports";"to
      }' > ${WORKING_DIRECTORY}/.tcp6-dnat-exposures

      echo "[Info] $(wc -l ${WORKING_DIRECTORY}/.tcp6-dnat-exposures | awk '{print $1}') records have been saved in ${WORKING_DIRECTORY}/.tcp6-dnat-exposures"

      ip6tables -t nat -S -w | grep '\--dport' | grep '\-p udp' | awk '{
         source = "::/0"; destination = "::/0"; dports = "N/A"; to = "N/A"
         for(i=1; i<=NF; i++) {
            if ($i == "-s" || $i == "--src-range") { source = $(i+1) }
            else if ($i == "-d") { destination = $(i+1) }
            else if ($i == "--dport" || $i == "--dports") { dports = $(i+1) }
            else if ($i == "--to-destination" || $i == "-j") { to = $(i+1) }
         }
         print source";"destination";"dports";"to
      }' > ${WORKING_DIRECTORY}/.udp6-dnat-exposures

      echo "[Info] $(wc -l ${WORKING_DIRECTORY}/.udp6-dnat-exposures | awk '{print $1}') records have been saved in ${WORKING_DIRECTORY}/.udp6-dnat-exposures"
   fi
}

#
# [Note] Concurrently process DNAT exposures: 
#
concurrent_process_dnat_exposures() {

   dump_dnat_strategy_tables

   abstract_concurrent_process "process_dnat_exposures" "${WORKING_DIRECTORY}/.tcp4-dnat-exposures"
   abstract_concurrent_process "process_dnat_exposures" "${WORKING_DIRECTORY}/.udp4-dnat-exposures"
   abstract_concurrent_process "process_dnat_exposures" "${WORKING_DIRECTORY}/.tcp6-dnat-exposures"
   abstract_concurrent_process "process_dnat_exposures" "${WORKING_DIRECTORY}/.udp6-dnat-exposures"

   writeback_temporary_file "${WORKING_DIRECTORY}/.tcp4-dnat-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.udp4-dnat-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.tcp6-dnat-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.udp6-dnat-exposures"
}

#
# [Note] Integrate with K8s perspective data to form a deeper analysis of pods.
#
recursive_track_k8s_pods() {

   local destination=$1
   local level=$2

   leve=$(expr $level + 1)

   echo "$destination" | echo sed "s#^#$(printf '%*s' $((level * 3 - 3)) )\`- #g" >> $filePath
}

#
# [Note] DNAT exposure perspective view subroutine, recursively tracks the iptables chain to the end pod IP.
#
recursive_track_iptables() {

   local linkName=$1
   local level=$2
   local filePath=$3
   local ipFamily=$4
   local IFS=$'\n'
   local i=

   if [ -z "$linkName" ] || [ -z "$level" ] || [ -z "$filePath" ]; then
      echo '[Warn] The current method relies on three input parameters: The link name of nat table, the indentation level and the dump file path.'
      return
   fi

   level=$(expr $level + 1)
   
   local iptablesBin=
   if [ -z "$ipFamily" ] || [ "$ipFamily" == "IPv4" ]; then
      iptablesBin=iptables
   elif [ "$ipFamily" == "IPv6" ]; then
      iptablesBin=ip6tables
   fi

   local portForwards=($($iptablesBin -t nat -S $linkName -w 2>/dev/null | grep -v -w '\-N' | grep -v 'MARK' | sed "s#^#$(printf '%*s' $((level * 3 - 3)) )\`- #g"))

   for i in ${portForwards[@]}; do

      echo "$portForwards" >> $filePath

      local linkName=$(echo "$i" | sed 's#.* -j \([^ ]*\)#\1#')

      if [ "$linkName" == "DNAT" ]; then
         local destination=$(echo "$line" | sed 's#.* --to-destination \([^ ]*\)#\1#')
         recursive_track_k8s_pods $destination $level
         continue
      else
         recursive_track_iptables $linkName $level $filePath $ipFamily
      fi
   done
}

#
# [Note] Show iptables DNAT exposures perspective
#
show_dnat_exposures_perspective() {

   local IFS=$'\n'
   local i=
   local linkName=

   if [ -f ${WORKING_DIRECTORY}/.tcp4-dnat-exposures ]; then
      if [ -f ${WORKING_DIRECTORY}/.tcp4-dnat-exposures-perspective ] && [ -s ${WORKING_DIRECTORY}/.tcp4-dnat-exposures-perspective ]; then
         cat ${WORKING_DIRECTORY}/.tcp4-dnat-exposures-perspective
      else
         local j=1
         for i in $(cat ${WORKING_DIRECTORY}/.tcp4-dnat-exposures); do
            echo "[$j] $i" | tee -a ${WORKING_DIRECTORY}/.tcp4-dnat-exposures-perspective
            j=$(expr $j + 1)
            linkName=$(echo "$i" | awk -F';' '{print $NF}')
            recursive_track_iptables "$linkName" 0 ${WORKING_DIRECTORY}/.tcp4-dnat-exposures-perspective 'IPv4'
         done
      fi
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp4-dnat-exposures ]; then
      if [ -f ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective ] && [ -s ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective ]; then
         cat ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective
      else
         local j=1
         for i in $(cat ${WORKING_DIRECTORY}/.udp4-dnat-exposures); do
            echo "[$j] $i" | tee -a ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective
            j=$(expr $j + 1)
            linkName=$(echo "$i" | awk -F';' '{print $NF}')
            recursive_track_iptables "$linkName" 0 ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective 'IPv4'
         done
      fi
   fi

   if [ -f ${WORKING_DIRECTORY}/.tcp6-dnat-exposures ]; then
      if [ -f ${WORKING_DIRECTORY}/.tcp6-dnat-exposures-perspective ] && [ -s ${WORKING_DIRECTORY}/.tcp6-dnat-exposures-perspective ]; then
         cat ${WORKING_DIRECTORY}/.tcp6-dnat-exposures-perspective
      else
         local j=1
         for i in $(cat ${WORKING_DIRECTORY}/.tcp6-dnat-exposures); do
            echo "[$j] $i" | tee -a ${WORKING_DIRECTORY}/.tcp6-dnat-exposures-perspective
            j=$(expr $j + 1)
            linkName=$(echo "$i" | awk -F';' '{print $NF}')
            recursive_track_iptables "$linkName" 0 ${WORKING_DIRECTORY}/.udp4-dnat-exposures-perspective 'IPv6'
         done
      fi
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp6-dnat-exposures ]; then
      if [ -f ${WORKING_DIRECTORY}/.udp6-dnat-exposures-perspective ] && [ -s ${WORKING_DIRECTORY}/.udp6-dnat-exposures-perspective ]; then
         cat ${WORKING_DIRECTORY}/.udp6-dnat-exposures-perspective
      else
         local j=1
         for i in $(cat ${WORKING_DIRECTORY}/.udp6-dnat-exposures); do
            echo "[$j] $i" | tee -a ${WORKING_DIRECTORY}/.udp6-dnat-exposures-perspective
            j=$(expr $j + 1)
            linkName=$(echo "$i" | awk -F';' '{print $NF}')
            recursive_track_iptables "$linkName" 0 ${WORKING_DIRECTORY}/.udp6-dnat-exposures-perspective 'IPv6'
         done
      fi
   fi
}

#
# [Note] When there are many listening ports, the performance of sequentially processing port listening exposed surfaces is poor.
#
sequential_process_listening_exposures() {

   local IFS=$'\n'
   local i=

   load_external_ip_addresses_from_file

   # Reset TCP/UDP listening exposures raw file
   >${WORKING_DIRECTORY}/.tcp4-listening-exposures
   >${WORKING_DIRECTORY}/.tcp6-listening-exposures
   >${WORKING_DIRECTORY}/.udp4-listening-exposures
   >${WORKING_DIRECTORY}/.udp6-listening-exposures

   # Generate TCP4 listening ports
   for i in $(ss -4nltp | awk '{print $4,$5,$6}' | tail -n +2); do
      local listenHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$i" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      if $(check_if_subnet_in_exposure "$listenHost"); then
         if [ "$listenHost" == "*" ]; then
            # The asterisk means listening on both IPv4 and IPv6 wildcard addresses simultaneously. Therefore, it is expanded into two listening records.
            local remoteHost=$(echo "$i" | awk '{print $2}')
            local note=$(echo "$i" | awk '{print $3}')
            echo "0.0.0.0:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
            echo "[::]:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
         else
            echo $i >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
         fi
      fi
   done

   # Generate TCP6 listening ports
   for i in $(ss -6nltp | awk '{print $4,$5,$6}' | tail -n +2); do
      local listenHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$i" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      if $(check_if_subnet_in_exposure "$listenHost"); then
         if [ "$listenHost" == "*" ]; then
            # The asterisk means listening on both IPv4 and IPv6 wildcard addresses simultaneously. Therefore, it is expanded into two listening records.
            local remoteHost=$(echo "$i" | awk '{print $2}')
            local note=$(echo "$i" | awk '{print $3}')
            echo "0.0.0.0:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
            echo "[::]:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
         else
            echo $i >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
         fi
      fi
   done

   # Generate UDP4 listening ports
   for i in $(ss -4nlup | awk '{print $4,$5,$6}' | tail -n +2); do
      local listenHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$i" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      if $(check_if_subnet_in_exposure "$listenHost"); then
         if [ "$listenHost" == "*" ]; then
            local remoteHost=$(echo "$i" | awk '{print $2}')
            local note=$(echo "$i" | awk '{print $3}')
            echo "0.0.0.0:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.udp4-listening-exposures
            echo "[::]:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.udp6-listening-exposures
         else
            echo $i >> ${WORKING_DIRECTORY}/.udp4-listening-exposures
         fi
      fi
   done

   # Generate UDP6 listening ports
   for i in $(ss -6nlup | awk '{print $4,$5,$6}' | tail -n +2); do
      local listenHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$i" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      if $(check_if_subnet_in_exposure "$listenHost"); then
         if [ "$listenHost" == "*" ]; then
            local remoteHost=$(echo "$i" | awk '{print $2}')
            local note=$(echo "$i" | awk '{print $3}')
            echo "0.0.0.0:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.udp4-listening-exposures
            echo "[::]:$listenPort $remoteHost $note" >> ${WORKING_DIRECTORY}/.udp6-listening-exposures
         else
            echo $i >> ${WORKING_DIRECTORY}/.udp6-listening-exposures
         fi
      fi
   done
}

#
# [Note] Single process processing of listening ports dump file specified by parameter 1. The starting and ending lines of the next two parameters indicate the scope of the processed file content.
#
process_listening_exposures() {

   local filePath=$1
   local beginLineNo=$2
   local endLineNo=$3
   local IFS=$'\n'
   local parentDirectory=$(dirname $filePath)
   local fileName=$(basename $filePath)
   local temporaryFilePath="$fileName.tmp"
   local temporaryFilePath_IPv4="$parentDirectory/$(echo $fileName | tr '0-9' '4').tmp"
   local temporaryFilePath_IPv6="$parentDirectory/$(echo $fileName | tr '0-9' '6').tmp"
   local k=
   local protocol=$(echo "$fileName" | grep -oE 'tcp|udp')

   if [ -z "$filePath" ] || [ -z "$beginLineNo" ] || [ -z "$endLineNo" ]; then
      echo '[Warn] This function need 3 parameters: the iptables strategies file path, the begin line number and the end line number of this file.'
      exit -1
   fi

   for k in $(sed -n "$beginLineNo,$endLineNo"p $filePath); do

      local listenHost=$(echo "$k" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$k" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      local remoteHost=$(echo "$k" | awk '{print $2}')

      # Filter out non-exposed ports
      if $(check_if_subnet_in_exposure "$listenHost"); then

         local note=$(echo "$k" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}')
         local portComment=$(grep -w "$listenPort/$protocol" /etc/services | sed 's#^\([^ ]*\).*\#\ \(.*\)#[\1] [\2]#')
         note="$note$portComment"

         if [ "$listenHost" == "*" ]; then
            # The asterisk means listening on both IPv4 and IPv6 wildcard addresses simultaneously. Therefore, it is expanded into two listening records.
            echo "0.0.0.0:$listenPort $remoteHost $note" >> $temporaryFilePath_IPv4
            echo "[::]:$listenPort $remoteHost $note" >> $temporaryFilePath_IPv6
         else
            echo "$listenHost:$listenPort $remoteHost $note" >> $temporaryFilePath
         fi
      fi

   done
}

#
# [Note] Obtaining raw listening information for TCP4/6 and UDP4/6 using ss tool. The accuracy of the data in the listening table depends on the accuracy of the external IP4/6 addresses. There is a high probability that the obtained external IP4/6 addresses will be greater than the actual external IP4/6 addresses. If a private IPv6 address is identified as an external IPv6 address, it will cause the extracted listening range to be greater than the actual listening range.
#
dump_listening_tables() {

   load_external_ip_addresses_from_file

   # Reset TCP/UDP listening exposures raw file
   >${WORKING_DIRECTORY}/.tcp4-listening-exposures
   >${WORKING_DIRECTORY}/.tcp6-listening-exposures
   >${WORKING_DIRECTORY}/.udp4-listening-exposures
   >${WORKING_DIRECTORY}/.udp6-listening-exposures

   if [ ${#EXTERNAL_IPV4_ADDRESSES[@]} -ne 0 ]; then
      # ss -4nltp -e | sed 's/%[^:]*:/:/g' | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
      # ss -4nlup -e | sed 's/%[^:]*:/:/g' | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp4-listening-exposures
      # [Fixed] Incomplete display of exposed surface information
      ss -4nltp -e | sed 's/%[^:]*:/:/g' | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
      ss -4nlup -e | sed 's/%[^:]*:/:/g' | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp4-listening-exposures

      local n_tcp4=$(wc -l ${WORKING_DIRECTORY}/.tcp4-listening-exposures | awk '{print $1}')
      local n_udp4=$(wc -l ${WORKING_DIRECTORY}/.udp4-listening-exposures | awk '{print $1}')

      echo "[Info] $n_tcp4 TCP4 listening strategies have been saved in ${WORKING_DIRECTORY}/.tcp4-listening-exposures"
      echo "[Info] $n_udp4 UDP4 listening strategies have been saved in ${WORKING_DIRECTORY}/.udp4-listening-exposures"
   fi

   if [ ${#EXTERNAL_IPV6_ADDRESSES[@]} -ne 0 ]; then
      # ss -6nltp -e | sed 's/%[^:]*:/:/g' | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
      # ss -6nlup -e | sed 's/%[^:]*:/:/g' | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp6-listening-exposures
      ss -6nltp -e | sed 's/%[^:]*:/:/g' | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
      ss -6nlup -e | sed 's/%[^:]*:/:/g' | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp6-listening-exposures

      local n_tcp6=$(wc -l ${WORKING_DIRECTORY}/.tcp6-listening-exposures | awk '{print $1}')
      local n_udp6=$(wc -l ${WORKING_DIRECTORY}/.udp6-listening-exposures | awk '{print $1}')

      echo "[Info] $n_tcp6 TCP6 listening strategies have been saved in ${WORKING_DIRECTORY}/.tcp6-listening-exposures"
      echo "[Info] $n_udp6 UDP6 listening strategies have been saved in ${WORKING_DIRECTORY}/.udp6-listening-exposures"
   fi
}

#
# [Note] Concurrently process listening exposures: 
#
concurrent_process_listening_exposures() {

   dump_listening_tables

   abstract_concurrent_process "process_listening_exposures" "${WORKING_DIRECTORY}/.tcp4-listening-exposures"
   abstract_concurrent_process "process_listening_exposures" "${WORKING_DIRECTORY}/.udp4-listening-exposures"
   abstract_concurrent_process "process_listening_exposures" "${WORKING_DIRECTORY}/.tcp6-listening-exposures"
   abstract_concurrent_process "process_listening_exposures" "${WORKING_DIRECTORY}/.udp6-listening-exposures"

   writeback_temporary_file "${WORKING_DIRECTORY}/.tcp4-listening-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.udp4-listening-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.tcp6-listening-exposures"
   writeback_temporary_file "${WORKING_DIRECTORY}/.udp6-listening-exposures"
}

#
# [Note] Merge TCP4 DNAT exposures and TCP4 listening exposures to TCP4 exposures, Merge UDP4 DNAT exposures and UDP4 listening exposures to UDP4 exposures, Merge TCP6 DNAT exposures and TCP6 listening exposures to TCP6 exposures, Merge UDP6 DNAT exposures and UDP6 listening exposures to UDP6 exposures.
#
merge_exposures() {

   load_external_ip_addresses_from_file

   # [1] Generate TCP4 exposures
   # Format TCP4 DNAT exposures: [1] 0.0.0.0/0;<port> → 0.0.0.0:<port> [2] 0.0.0.0:<port1>,<port2> → 0.0.0.0:<port1> and 0.0.0.0:<port2> [3] unique sort
   local tcp4DnatExposures=()
   if [ -f ${WORKING_DIRECTORY}/.tcp4-dnat-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp4-dnat-exposures ]; then
      tcp4DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print $2":"$3}' ${WORKING_DIRECTORY}/.tcp4-dnat-exposures | awk -F: '{
         split($2, ports, ",")
         for (i in ports) {
            print $1 ":" ports[i]
         }
      }' | sort -u))
   fi

   # Format TCP4 Listening exposures
   local tcp4ListeningExposures=()
   if [ -f ${WORKING_DIRECTORY}/.tcp4-listening-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp4-listening-exposures ]; then
      tcp4ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.tcp4-listening-exposures | sort -u))
   fi

   # Merge TCP4 exposures
   local tcp4Exposures=( ${tcp4DnatExposures[@]} ${tcp4ListeningExposures[@]} )

   if [ ${#tcp4Exposures[@]} -ne 0 ]; then

      # Eliminate duplicates and save to temporary file
      echo ${tcp4Exposures[@]} | tr ' ' '\n' | sort -u > ${WORKING_DIRECTORY}/.tcp4-exposures.tmp

      # Convert wildcard exposures 0.0.0.0 to specific exposed addresses ( external IP )
      awk -F: -v ips="${EXTERNAL_IPV4_ADDRESSES[*]}" '
         BEGIN {
            split(ips, ip_array, " ")
         }
         {
            if ($1 == "0.0.0.0") {
               for (i in ip_array) {
                  print ip_array[i] ":" $2
               }
            } else {
               print $0
            }
         }' ${WORKING_DIRECTORY}/.tcp4-exposures.tmp | sort -u > ${WORKING_DIRECTORY}/.tcp4-exposures
      
      # Remove temporary file
      /usr/bin/rm -f ${WORKING_DIRECTORY}/.tcp4-exposures.tmp

      local n_tcp4=$(wc -l ${WORKING_DIRECTORY}/.tcp4-exposures | awk '{print $1}')
      echo "[Info] $n_tcp4 TCP4 exposures have been saved in ${WORKING_DIRECTORY}/.tcp4-exposures"
   fi

   # [2] Generate UDP4 exposures
   # Format UDP4 DNAT exposures: [1] 0.0.0.0/0;<port> → 0.0.0.0:<port> [2] 0.0.0.0:<port1>,<port2> → 0.0.0.0:<port1> and 0.0.0.0:<port2> [3] unique sort
   local udp4DnatExposures=()
   if [ -f ${WORKING_DIRECTORY}/.udp4-dnat-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp4-dnat-exposures ]; then
      udp4DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print $2":"$3}' ${WORKING_DIRECTORY}/.udp4-dnat-exposures | awk -F: '{
         split($2, ports, ",")
         for (i in ports) {
            print $1 ":" ports[i]
         }
      }' | sort -u))
   fi

   # Format UDP4 Listening exposures
   local udp4ListeningExposures=()
   if [ -f ${WORKING_DIRECTORY}/.udp4-listening-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp4-listening-exposures ]; then
      udp4ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.udp4-listening-exposures | sort -u))
   fi

   # Merge UDP4 exposures
   local udp4Exposures=( ${udp4DnatExposures[@]} ${udp4ListeningExposures[@]} )

   if [ ${#udp4Exposures[@]} -ne 0 ]; then

      # Eliminate duplicates and save to temporary file
      echo ${udp4Exposures[@]} | tr ' ' '\n' | sort -u > ${WORKING_DIRECTORY}/.udp4-exposures.tmp

      # Convert wildcard exposures 0.0.0.0 to specific exposed addresses ( external IP )
      awk -F: -v ips="${EXTERNAL_IPV4_ADDRESSES[*]}" '
         BEGIN {
            split(ips, ip_array, " ")
         }
         {
            if ($1 == "0.0.0.0") {
               for (i in ip_array) {
                  print ip_array[i] ":" $2
               }
            } else {
               print $0
            }
         }' ${WORKING_DIRECTORY}/.udp4-exposures.tmp | sort -u > ${WORKING_DIRECTORY}/.udp4-exposures
      
      # Remove temporary file
      /usr/bin/rm -f ${WORKING_DIRECTORY}/.udp4-exposures.tmp

      local n_udp4=$(wc -l ${WORKING_DIRECTORY}/.udp4-exposures | awk '{print $1}')
      echo "[Info] $n_udp4 UDP4 exposures have been saved in ${WORKING_DIRECTORY}/.udp4-exposures"
   fi

   # [3] Generate TCP6 exposures
   # Format TCP6 DNAT exposures:
   # ::/0;<port> → [::]:<port>
   # [::]:<port1>,<port2>,... → [::]:<port1> [::]:<port2> ...
   # unique sort
   local tcp6DnatExposures=()
   if [ -f ${WORKING_DIRECTORY}/.tcp6-dnat-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp6-dnat-exposures ]; then
      tcp6DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print "["$2"]:"$3}' ${WORKING_DIRECTORY}/.tcp6-dnat-exposures | awk -F']:' '{
         split($2, ports, ",")
         for (i in ports) {
            print $1 "]:" ports[i]
         }
      }' | sort -u))
   fi

   # Format TCP6 Listening exposures
   local tcp6ListeningExposures=()
   if [ -f ${WORKING_DIRECTORY}/.tcp6-listening-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp6-listening-exposures ]; then
      tcp6ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.tcp6-listening-exposures | sort -u))
   fi

   # Merge TCP6 exposures
   local tcp6Exposures=( ${tcp6DnatExposures[@]} ${tcp6ListeningExposures[@]} )

   if [ ${#tcp6Exposures[@]} -ne 0 ]; then

      # Eliminate duplicates and save to temporary file
      echo ${tcp6Exposures[@]} | tr ' ' '\n' | sort -u > ${WORKING_DIRECTORY}/.tcp6-exposures.tmp

      # Convert wildcard exposures [::] to specific exposed addresses ( external IP )
      awk -F']:' -v ips="${EXTERNAL_IPV6_ADDRESSES[*]}" '
         BEGIN {
            split(ips, ip_array, " ")
         }
         {
            if ($1 == "[::") {
               for (i in ip_array) {
                  print "[" ip_array[i] "]:" $2
               }
            } else {
               print $0
            }
         }' ${WORKING_DIRECTORY}/.tcp6-exposures.tmp | sort -u > ${WORKING_DIRECTORY}/.tcp6-exposures
      
      # Remove temporary file
      /usr/bin/rm -f ${WORKING_DIRECTORY}/.tcp6-exposures.tmp

      local n_tcp6=$(wc -l ${WORKING_DIRECTORY}/.tcp6-exposures | awk '{print $1}')
      echo "[Info] $n_tcp6 TCP6 exposures have been saved in ${WORKING_DIRECTORY}/.tcp6-exposures"
   fi

   # [4] Generate UDP6 exposures
   local udp6DnatExposures=()
   if [ -f ${WORKING_DIRECTORY}/.udp6-dnat-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp6-dnat-exposures ]; then
      udp6DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print "["$2"]:"$3}' ${WORKING_DIRECTORY}/.udp6-dnat-exposures | awk -F']:' '{
         split($2, ports, ",")
         for (i in ports) {
            print $1 "]:" ports[i]
         }
      }' | sort -u))
   fi

   # Format UDP6 Listening exposures
   local udp6ListeningExposures=()
   if [ -f ${WORKING_DIRECTORY}/.udp6-listening-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp6-listening-exposures ]; then
      udp6ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.udp6-listening-exposures | sort -u))
   fi

   # Merge UDP6 exposures
   local udp6Exposures=( ${udp6DnatExposures[@]} ${udp6ListeningExposures[@]} )

   if [ ${#udp6Exposures[@]} -ne 0 ]; then

      # Eliminate duplicates and save to temporary file
      echo ${udp6Exposures[@]} | tr ' ' '\n' | sort -u > ${WORKING_DIRECTORY}/.udp6-exposures.tmp

      # Convert wildcard exposures [::] to specific exposed addresses ( external IP )
      awk -F']:' -v ips="${EXTERNAL_IPV6_ADDRESSES[*]}" '
         BEGIN {
            split(ips, ip_array, " ")
         }
         {
            if ($1 == "[::") {
               for (i in ip_array) {
                  print "[" ip_array[i] "]:" $2
               }
            } else {
               print $0
            }
         }' ${WORKING_DIRECTORY}/.udp6-exposures.tmp | sort -u > ${WORKING_DIRECTORY}/.udp6-exposures
      
      # Remove temporary file
      /usr/bin/rm -f ${WORKING_DIRECTORY}/.udp6-exposures.tmp

      local n_udp6=$(wc -l ${WORKING_DIRECTORY}/.udp6-exposures | awk '{print $1}')
      echo "[Info] $n_udp6 UDP6 exposures have been saved in ${WORKING_DIRECTORY}/.udp6-exposures"
   fi
}

#
# [Note] Preventive iptables strategies opening (预防性策略放通) is necessary to prevent ports from being inaccessible during wildcard network security reinforcement on the host. For example, adding the 0.0.0.0/0 to 0.0.0.0/0 ANY REJECT policy may cause communication failure between containers sharing the same docker container bridge on the current node. Therefore, it is necessary to open the DOCKER-BRIDGE-SUBNET TO DOCKER-BRIDGE-SUBNET ANY ALLOW strategy.
#
preventive_iptables_allow_rules() {

   local i=
   local params="${*}"
   
   load_default_route_ip_addresses_from_file --no-cache
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_service_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file
   # Don't forget the loopback subnets

   overwrite_shell_script_header ${WORKING_DIRECTORY}/.preventive-allow-script

   echo >> ${WORKING_DIRECTORY}/.preventive-allow-script
   # Ignore the error message that IPsec already exists, support automatic loading after host restart and regularly execute strategy repairs
   echo "ipset create permit-subnets-ipv4 hash:net 2>/dev/null" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ipset create permit-subnets-ipv6 hash:net family inet6 2>/dev/null" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   # During the period of open business production, regular strategy repairs should be carried out, and it is best not to reset the strategy, otherwise there may be a risk of some connections crashing. Then, here, parameter control is used.
   if [[ "$params" =~ "--flush-ipset" ]]; then
      echo "ipset flush permit-subnets-ipv4" >> ${WORKING_DIRECTORY}/.preventive-allow-script
      echo "ipset flush permit-subnets-ipv6" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   fi

   echo >> ${WORKING_DIRECTORY}/.preventive-allow-script
   for i in ${DEFAULT_IPV4_ROUTE_ADDRESSES[@]} ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${SERVICE_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${LOOPBACK_SUBNETS_IPV4}; do
      echo "ipset add permit-subnets-ipv4 $i" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   done

   echo >> ${WORKING_DIRECTORY}/.preventive-allow-script
   for i in ${DEFAULT_IPV6_ROUTE_ADDRESSES[@]} ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${SERVICE_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${LOOPBACK_SUBNETS_IPV6}; do
      echo "ipset add permit-subnets-ipv6 $i" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   done

   # Communications in TCP4/UDP4
   echo >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "iptables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv4 src -m set --match-set permit-subnets-ipv4 dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "iptables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv4 src -m set --match-set permit-subnets-ipv4 dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   # Communications in TCP6/UDP6
   echo >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ip6tables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv6 src -m set --match-set permit-subnets-ipv6 dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ip6tables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv6 src -m set --match-set permit-subnets-ipv6 dst -m comment --comment \"${IPTABLES_COMMENT}\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   sed -i '/^$/N;/^\n$/D' ${WORKING_DIRECTORY}/.preventive-allow-script

   echo "[Info] The preventive iptables allow rules have been saved in ${WORKING_DIRECTORY}/.preventive-allow-script"
}

#
# [Note] Generate packet filtering conditions based on the merged exposed surface files
#
get_packets_filter_file_by_exposures () {

   # Load private client subnets of current host. It should be noted that service CIDR can only be used as the destination, not as the client. In addition, traffic capture will be performed on external network interfaces rather than [any], so the filtering conditions for the loopback network can be ignored.
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file

   # [Fixed] It is a difficult decision whether the traffic between nodes within the K8s cluster should be captured and whether it should be released by default. If released by default, it will inevitably increase the risk exposure surface. If a node in the cluster is breached, it may bring significant security risks to the entire cluster. If policy convergence, i.e. strong blocking strategy, is also required within the cluster, it will result in an increase in the number of subsequent iptables policies and pose performance risks.
   # load_k8s_nodes_ip_addresses_from_file

   # [1] TCP4 filters
   if [ -f ${WORKING_DIRECTORY}/.tcp4-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp4-exposures ]; then

      echo '[Info] TCP4 filters:'

      # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
      echo -n 'ip and tcp' | tee ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter

      # Filter out request packets from private subnets
      for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${K8S_NODES_IPV4_SUBNETS[@]}; do
         echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter
      done

      # Add destination address filtering criteria
      echo -n ' and ( ' | tee -a .tcp4-exposures-packets-filter
      awk -F: '{a[$1]=a[$1]?a[$1]" or dst port "$2:$2} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' ${WORKING_DIRECTORY}/.tcp4-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter
      echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter
   fi

   # [2] UDP4 filters
   if [ -f ${WORKING_DIRECTORY}/.udp4-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp4-exposures ]; then

      echo -e '\n[Info] UDP4 filters:'

      # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
      echo -n 'ip and udp' | tee ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter

      # Filter out request packets from private subnets
      for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${K8S_NODES_IPV4_SUBNETS[@]}; do
         echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
      done

      # Add destination address filtering criteria
      echo -n ' and ( ' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
      awk -F: '{a[$1]=a[$1]?a[$1]" or dst port "$2:$2} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' ${WORKING_DIRECTORY}/.udp4-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
      echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
   fi

   # [3] TCP6 filters
   if [ -f ${WORKING_DIRECTORY}/.tcp6-exposures ] && [ -s ${WORKING_DIRECTORY}/.tcp6-exposures ]; then

      echo -e '\n[Info] TCP6 filters:'
      
      # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
      echo -n 'ip6 and tcp' | tee ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter

      # Filter out request packets from private subnets
      for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${K8S_NODES_IPV6_SUBNETS[@]}; do
         echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter
      done

      # Add destination address filtering criteria
      echo -n ' and ( ' | tee -a .tcp6-exposures-packets-filter
      awk -F']:' '{addr = $1; port = $2; gsub(/^\[/, "", addr); a[addr]=a[addr]?a[addr]" or dst port "port:port} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' ${WORKING_DIRECTORY}/.tcp6-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter
      echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter
   fi

   # [4] UDP6 filters
   if [ -f ${WORKING_DIRECTORY}/.udp6-exposures ] && [ -s ${WORKING_DIRECTORY}/.udp6-exposures ]; then

      echo -e '\n[Info] UDP6 filters:'

      # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
      echo -n 'ip6 and udp' | tee ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter

      # Filter out request packets from private subnets
      for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]}  ${K8S_NODES_IPV6_SUBNETS[@]}; do
         echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
      done

      # Add destination address filtering criteria
      echo -n ' and ( ' | tee -a .udp6-exposures-packets-filter
      awk -F']:' '{addr = $1; port = $2; gsub(/^\[/, "", addr); a[addr]=a[addr]?a[addr]" or dst port "port:port} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' ${WORKING_DIRECTORY}/.udp6-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
      echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
   fi
}

#
# [Note] Prerequisites: The current method reads the external network interface names from the .external-interfaces hidden file. If it has not been created or the file content is empty, then will call network-tilities.sh to obtain it. This method will output the tcpdump packet capture script hidden file.
#
get_packets_capture_script() {

   load_external_interfaces_from_file

   >${WORKING_DIRECTORY}/.packets-capture-scripts

   local i=
   for i in ${EXTERNAL_INTERFACES[@]}; do

      if [ -f ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter ]; then
         echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts
      fi

      if [ -f ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter ]; then
         echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts
      fi

      if [ -f ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter ]; then
         echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts
      fi

      if [ -f ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter ]; then
         echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts
      fi
   done

   echo "[Info] Packets capture scripts have saved in ${WORKING_DIRECTORY}/.packets-capture-scripts"
}

#
# [Note] Generate tcpdump packet capture script, which carries MAC address fingerprints in the traffic data for identifying the identity of visiting IP addresses (身份核实). It is relatively effective for dynamically allocating client addresses, avoiding situations where access is not possible after IP changes. Therefore, MAC release strategy can be an effective supplement to IP release strategy.
#
get_packets_capture_with_mac_fingerprint_script() {

   load_external_interfaces_from_file

   >${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac

   local i=
   for i in ${EXTERNAL_INTERFACES[@]}; do

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter -e" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter -e" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter -e" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter -e" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac
   done

   echo "[Info] Packets capture scripts have saved in ${WORKING_DIRECTORY}/.packets-capture-scripts-with-mac"
}

#
# [Note] Use tcpdump to capture packets and extract connections summary, including extract important fields and eliminate duplicate data.
#
run_capture_and_summarize_connections() {

   local tcpdumpScript="${*}"
   local protoType=$(echo "$tcpdumpScript" | sed 's#.*\.\([cdtup46]*\)-exposures-packets-filter$#\1#g')
   local connectionSummaryPath=${WORKING_DIRECTORY}/.$protoType-connections-summary

   if [ -z "$tcpdumpScript" ] || [ -z "$protoType" ]; then
      echo '[Info] Please provide a valid packet capture script.'
      exit -1
   fi

   # By default, historical data will be retained, allowing for long-term and multiple traffic summaries
   if ${RESET_CONNECTIONS_SUMMARY_HISTORY}; then
      >$connectionSummaryPath
   fi

   eval "$tcpdumpScript" 2>/dev/null | while IFS= read -r line; do
      
      local packet=

      if [ $(echo "$line" | grep -w 'IP' | wc -l) -ne 0 ]; then
         # IPv4 Packets
         # "10:38:24.430299 IP 10.17.249.131.31794 > 10.17.249.98.44444: tcp 0" → "10.17.249.131,10.17.249.98.44444"
         packet=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5} > ([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5}' | sed 's/\.[0-9]* > /,/g')
      elif [ $(echo "$line" | grep -w 'IP6' | wc -l) -ne 0 ]; then
         # IPv6 Packets
         # "10:11:20.174380 IP6 2001:db8::1.10884 > 2001:db8::2.10250: tcp 0" → "2001:db8::1,2001:db8::2.10250"
         packet=$(echo "$line" | awk '{print $3,$5}' | sed 's#^\([^.]*\)\.[0-9]*\ \([^.]*\)\.\([0-9]*\).*#\1,\2.\3#g')
      fi

      if [ $(echo "$packet" | grep "^$" | wc -l) -ne 0 ]; then
         # Check Empty lines
         continue
      fi

      # Add parameter FX to avoid partial content matching
      if [ $(grep -Fx $packet $connectionSummaryPath | wc -l) -eq 0 ]; then
         echo $packet >> $connectionSummaryPath
      fi
   done

   echo "[Info] The packets have been summarized into file $connectionSummaryPath"
}

#
# [Note] Use tcpdump to capture packets and extrace connections summary, including mac fingerprints.
#
run_capture_with_mac_fingerprint_and_summarize_connections() {

   local tcpdumpScript="${*}"
   local protoType=$(echo "$tcpdumpScript" | sed 's#.*\.\([cdtup46]*\)-exposures-packets-filter$#\1#g')
   local connectionSummaryPath=${WORKING_DIRECTORY}/.$protoType-connections-summary

   if [ -z "$tcpdumpScript" ] || [ -z "$protoType" ]; then
      echo '[Info] Please provide a valid packet capture script.'
      exit -1
   fi

   >$connectionSummaryPath

   eval "$tcpdumpScript" 2>/dev/null | while IFS= read -r line; do
      
      local packet=

      if [ $(echo "$line" | grep -w 'IP' | wc -l) -ne 0 ]; then
         # IPv4 Packets
         # "15:35:49.173161 6c:9c:ed:41:cf:42 > ac:4e:91:61:68:15, IPv4, length 66: 134.80.135.140.22948 > 10.17.249.131.22: tcp 0" → "6c:9c:ed:41:cf:42,134.80.135.140,10.17.249.131.22"
         packet=$(echo "$line" |  awk '{print $2,$8,$10}' | sed 's#^\([^ ]*\)\ \(.*\)\.[0-9]*\ \(.*\)\.\([0-9]*\):$#\1,\2,\3:\4#g')
      elif [ $(echo "$line" | grep -w 'IP6' | wc -l) -ne 0 ]; then
         # IPv6 Packets
         # "10:11:20.174380 IP6 2001:db8::1.10884 > 2001:db8::2.10250: tcp 0" → "2001:db8::1,2001:db8::2.10250"
         packet=$(echo "$line" | awk '{print $2,$8,$10}' | sed 's#^\([^ ]*\)\ ^\([^.]*\)\.[0-9]*\ \([^.]*\)\.\([0-9]*\).*#\1,\2,\3:\4#g')
      fi

      if [ $(echo "$packet" | grep "^$" | wc -l) -ne 0 ]; then
         # Check Empty lines
         continue
      fi

      # Add parameter FX to avoid partial content matching
      if [ $(grep -Fx $packet $connectionSummaryPath | wc -l) -eq 0 ]; then
         echo $packet >> $connectionSummaryPath
      fi
   done

   echo "[Info] The packets have been summarized into file $connectionSummaryPath"
}

#
# [Note] Create a process to execute concurrently for each packet capture command.
#
concurrently_run_packets_captures() {

   if [ ! -f ${WORKING_DIRECTORY}/.packets-capture-scripts ]; then
      echo "[Warn] Cannot find file ${WORKING_DIRECTORY}/.packets-capture-scripts"
      exit -1
   fi

   local IFS=$'\n'
   local tcpdumpScript=

   for tcpdumpScript in $(cat ${WORKING_DIRECTORY}/.packets-capture-scripts); do

      local processNumber=$(ps -ef | grep "$tcpdumpScript" | grep -v grep | wc -l)
      if [ $processNumber -ne 0 ]; then
         echo '[Warn] There are still unfinished packet capture processes.'
         continue
      fi

      nohup $0 --run-capture-and-summarize-connections "$tcpdumpScript" &
   done
}

get_exposure_comments() {
   
   local protocol=$1
   local destinationHost=$2
   local destinationPort=$3

   if [ -z "$protocol" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ]; then
      return
   fi

   # 1. Query in DNAT exposures
   if [ ! -f ${WORKING_DIRECTORY}/.$protocol-dnat-exposures ]; then
      return
   fi

   for i in $(cat ${WORKING_DIRECTORY}/.$protocol-dnat-exposures); do
      local dnatHost=$(echo "$i" | awk -F';' '{print $2}')
      local dnatPort=$(echo "$i" | awk -F';' '{print $3}')
      local jumpTo=$(echo "$i" | awk -F';' '{print $4}')

      if [ "$destinationPort" == "$dnatPort" ]; then

         local match=$(python3 ${WORKING_DIRECTORY}/network-utilities.py --check-ip-in-pools "$destinationHost" "$dnatHost" | tr '[:upper:]' '[:lower:]')

         if $match; then
            echo "$jumpTo"
            return
         fi
      fi
   done

   # 2. Query in listening exposures
   grep -E "^$destinationHost:$destinationPort|^0.0.0.0:$destinationPort" ${WORKING_DIRECTORY}/.$protocol-listening-exposures | head -1 | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}'
}

#
# [Note] Generate ipset update scripts
#
get_ipset_config_scripts() {

   local protocol=$1
   local destinationHost=$2
   local destinationPort=$3
   local sourceHosts=("${@:4}")
   local ipsetName='allowed_'$protocol'_to_'$destinationHost':'$destinationPort
   local ipFamily=$(echo "$protocol" | grep -oE '4|6')
   local ipsetSuffix="$([ $ipFamily -eq 6 ] && echo ' family inet6')"
   local k8sNodes=()

   load_k8s_nodes_ip_addresses_from_file
   if [ $ipFamily -eq 4 ]; then
      k8sNodes=(${K8S_NODES_IPV4_ADDRESSES[@]})
   elif [ $ipFamily -eq 6 ]; then
      k8sNodes=(${K8S_NODES_IPV6_ADDRESSES[@]})
   fi

   # ipset configurations only appears during the strategy creation phase
   local scriptPath=${WORKING_DIRECTORY}/.$protocol-exposures-allow-script

   if [ -z "$protocol" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ] || [ ${#sourceHosts[@]} -eq 0 ] || [ -z "$ipFamily" ]; then
      echo '[Warn] Please provide valid parameters: <protocol: tcp4|udp4|tcp6|udp6> <destinationHost> <destinationPort> <sourceHosts ..>'
      return
   fi

   # [Fixed] It is not recommended to directly delete ipset during daily maintenance, as iptables strategies may lock ipset and cause deletion failure. Exposed surface recycling, which has not occurred for a long time, can trigger the removal of iptables and ipset policies.
   if $(ipset list $ipsetName 1>/dev/null 2>/dev/null); then
      # Clearing ipset and restoring it in a timely manner theoretically can cause network connection interruptions
      echo "ipset flush $ipsetName" >> $scriptPath
   else
      echo "ipset create $ipsetName hash:ip$ipsetSuffix" >> $scriptPath
   fi

   # Supplement on the basis of [sourceHosts]
   # 1. Supplementary privileged/legacy connections strategies, the .legacy-connections file format is <legacy-client-ip>,<destination-server-ip>:<destination-server-port>,<protocol> # <the comments>
   # [Example] 192.168.0.1,192.168.0.2:38800,tcp4   # Account Service
   local legacyClients=($(awk '{print $1}' ${WORKING_DIRECTORY}/.legacy-connections | grep -w "$protocol" | awk -F, '{print $2,$1}' | group_by_1st_column_no_limit | grep "^$destinationHost:$destinationPort" | awk '{print $2}' | tr ',' '\n'))
   sourceHosts=(${sourceHosts[@]} ${legacyClients[@]})

   # 2. Supplement special port strategy
   # [Note] Check if sourceHosts contains K8s nodes IP addresses. Equivalent to: There is an intersection between the source address set in the "Connections Summary" and the K8s cluster address set. Based on the possibility that the client source on the K8s cluster address is dynamic, it needs to be extended to the entire K8s cluster address, which is the union of the two sets mentioned above.
   local -A seen
   local elem=
   local hasIntersection=false

   for elem in ${k8sNodes[@]}; do
      seen["$elem"]=1
   done

   for elem in "${sourceHosts[@]}"; do
      if [[ ${seen["$elem"]} ]]; then
         hasIntersection=true
         break
      fi
   done

   if $hasIntersection; then
      # The union of connections summary and K8s nodes
      sourceHosts=(${sourceHosts[@]} ${k8sNodes[@]})
   fi

   # Remove duplicates
   sourceHosts=($(echo ${sourceHosts[@]} | tr ' ' '\n' | sort -u))

   # Write to scripts file
   # [Note] Supplementing strategies may lead to policy redundancy, but this is a last resort. Firstly, it should be noted that K8s nodes may have the concept of virtual partitions, which are nodes that are forcibly isolated by setting taints to undertake different businesses. There is no container interaction between groups, so there is no need for VXLAN interoperability. However, in reality, VXLAN interoperability has been fully opened up here, and users can achieve it through policy isolation of different groups in the future.

   # Encapsulate the ipset restore command
   echo 'echo "' >> $scriptPath
   echo "${sourceHosts[@]}" | tr ' ' '\n' | sed "s#^#   add $ipsetName #g" >> $scriptPath
   echo '" | ipset restore' >> $scriptPath
}

#
# [Note] Generate a network policy release script based on network connection summary data. Note that network connection summary is not equivalent to the actual address range that should be opened. Client IP addresses assigned dynamically may not be included in the current traffic collection data. For client addresses in primary and backup modes, the connection summary may not be complete and need to be manually identified.
#
get_iptables_allow_rules_from_connections_summary() {

   local IFS=$'\n'
   local i=
   local j=

   if [ -f ${WORKING_DIRECTORY}/.tcp4-connections-summary ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script
      
      for i in $(awk -F, '{print $2,$1}' ${WORKING_DIRECTORY}/.tcp4-connections-summary | group_by_1st_column_no_limit); do

         local sourceHosts=($(echo "$i" | awk '{print $2}' | tr ',' '\n'))
         local destinationHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\1#g')
         local destinationPort=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\2#g')

         if [ -z "$sourceHosts" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ]; then
            # ignore invalid lines
            continue
         fi

         echo "# Permission rules for $destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script
         
         # Get and append strategy comments
         local comments=$(get_exposure_comments 'tcp4' $destinationHost $destinationPort)
         echo "# $comments" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

         get_ipset_config_scripts 'tcp4' $destinationHost $destinationPort "${sourceHosts[@]}"

         # The efficiency of sequentially adding ipset entries is low, and executing them during peak production periods will result in longer connection interruption times.
         # for j in ${sourceHosts[@]}; do
         #    echo "ipset add allowed_tcp4_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script
         # done

         echo "iptables -t raw -C PREROUTING -p tcp -m set --match-set allowed_tcp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

         echo "iptables -t raw -I PREROUTING -p tcp -m set --match-set allowed_tcp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

         echo >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

      done

      echo "[Info] The TCP4 allow rules have been saved in ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp4-connections-summary ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp4-exposures-allow-script
      
      for i in $(awk -F, '{print $2,$1}' ${WORKING_DIRECTORY}/.udp4-connections-summary | group_by_1st_column_no_limit); do

         local sourceHosts=($(echo "$i" | awk '{print $2}' | tr ',' '\n'))
         local destinationHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\1#g')
         local destinationPort=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\2#g')

         if [ -z "$sourceHosts" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ]; then
            # ignore invalid lines
            continue
         fi

         echo "# Permission rules for $destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         # Get and append strategy comments
         local comments=$(get_exposure_comments 'udp4' $destinationHost $destinationPort)
         echo "# $comments" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         get_ipset_config_scripts 'udp4' $destinationHost $destinationPort "${sourceHosts[@]}"

         # echo "ipset destroy allowed_udp4_to_$destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         # echo "ipset create allowed_udp4_to_$destinationHost:$destinationPort hash:ip" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         # for j in ${sourceHosts[@]}; do
         #    echo "ipset add allowed_udp4_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script
         # done

         echo "iptables -t raw -C PREROUTING -p udp -m set --match-set allowed_udp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         echo "iptables -t raw -I PREROUTING -p udp -m set --match-set allowed_udp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         echo >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

      done

      echo "[Info] The UDP4 allow rules have been saved in ${WORKING_DIRECTORY}/.udp4-exposures-allow-script"
   fi

   if [ -f ${WORKING_DIRECTORY}/.tcp6-connections-summary ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script
      
      for i in $(awk -F, '{print $2,$1}' ${WORKING_DIRECTORY}/.tcp6-connections-summary | group_by_1st_column_no_limit); do

         local sourceHosts=($(echo "$i" | awk '{print $2}' | tr ',' '\n'))
         local destinationHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\1#g')
         local destinationPort=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\2#g')

         if [ -z "$sourceHosts" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ]; then
            # ignore invalid lines
            continue
         fi

         echo "# Permission rules for $destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

         echo "ipset destroy allowed_tcp6_to_$destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

         echo "ipset create allowed_tcp6_to_$destinationHost:$destinationPort hash:ip" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

         for j in ${sourceHosts[@]}; do
            echo "ipset add allowed_tcp6_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script
         done

         echo "ip6tables -t raw -C PREROUTING -p tcp -m set --match-set allowed_tcp6_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

         echo "ip6tables -t raw -I PREROUTING -p tcp -m set --match-set allowed_tcp6_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

         echo >> ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script

      done

      echo "[Info] The TCP6 allow rules have been saved in ${WORKING_DIRECTORY}/.tcp6-exposures-allow-script"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp6-connections-summary ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp6-exposures-allow-script
      
      for i in $(awk -F, '{print $2,$1}' ${WORKING_DIRECTORY}/.udp6-connections-summary | group_by_1st_column_no_limit); do

         local sourceHosts=($(echo "$i" | awk '{print $2}' | tr ',' '\n'))
         local destinationHost=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\1#g')
         local destinationPort=$(echo "$i" | awk '{print $1}' | sed 's#^\(.*\)\.\([0-9]*\)$#\2#g')

         if [ -z "$sourceHosts" ] || [ -z "$destinationHost" ] || [ -z "$destinationPort" ]; then
            # ignore invalid lines
            continue
         fi

         echo "# Permission rules for $destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

         echo "ipset destroy allowed_udp6_to_$destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

         echo "ipset create allowed_udp6_to_$destinationHost:$destinationPort hash:ip" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

         for j in ${sourceHosts[@]}; do
            echo "ipset add allowed_udp6_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script
         done

         echo "ip6tables -t raw -C PREROUTING -p udp -m set --match-set allowed_udp6_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

         echo "ip6tables -t raw -I PREROUTING -p udp -m set --match-set allowed_udp6_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

         echo >> ${WORKING_DIRECTORY}/.udp6-exposures-allow-script

      done

      echo "[Info] The UDP6 allow rules have been saved in ${WORKING_DIRECTORY}/.udp6-exposures-allow-script"
   fi
}

#
# [Note] Generate iptables multiport blocking strategy scripts based on port exposure surface file. Compared to the ipset mode, the performance of multiport blocking is poor. If there are many listening ports, it is necessary to split them according to the upper limit of each group of 15 ports, resulting in too many iptables policies.
#
get_iptables_multiport_reject_rules_from_exposures() {

   local IFS=$'\n'
   local i=

   if [ -f ${WORKING_DIRECTORY}/.tcp4-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      # Performance improvement: Convert the list of <HOST_IP>:<EXPOSED_PORT> to <HOST_IP> <EXPOSED_PORT_1>[,<EXPOSED_PORT_1>...] format
      for i in $(awk -F':' '{print $1,$2}' ${WORKING_DIRECTORY}/.tcp4-exposures | group_by_1st_column); do
         
         local dstHost=$(echo "$i" | awk '{print $1}')
         local dstPorts=$(echo "$i" | awk '{print $2}')

         echo "iptables -t raw -C PREROUTING -d $dstHost -p tcp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject
         echo "iptables -t raw -A PREROUTING -d $dstHost -p tcp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject
      done

      echo "[Info] The TCP4 reject rules have been saved in ${WORKING_DIRECTORY}/.tcp4-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp4-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp4-exposures-reject

      # Convert the list of <HOST_IP>:<EXPOSED_PORT> to <HOST_IP> <EXPOSED_PORT_1>[,<EXPOSED_PORT_1>...] format
      for i in $(awk -F':' '{print $1,$2}' ${WORKING_DIRECTORY}/.udp4-exposures | group_by_1st_column); do
         
         local dstHost=$(echo "$i" | awk '{print $1}')
         local dstPorts=$(echo "$i" | awk '{print $2}')

         echo "iptables -t raw -C PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject
         echo "iptables -t raw -A PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject
      done

      echo "[Info] The UDP4 reject rules have been saved in ${WORKING_DIRECTORY}/.udp4-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.tcp6-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp6-exposures-reject

      # Convert the list of <HOST_IP>:<EXPOSED_PORT> to <HOST_IP> <EXPOSED_PORT_1>[,<EXPOSED_PORT_1>...] format
      for i in $(sed 's#^\[\(.*\)\]:\([0-9]*\)$#\1 \2#g' ${WORKING_DIRECTORY}/.tcp6-exposures | group_by_1st_column); do
         
         local dstHost=$(echo "$i" | awk '{print $1}')
         local dstPorts=$(echo "$i" | awk '{print $2}')

         echo "ip6tables -t raw -C PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject
         echo "ip6tables -t raw -A PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject
      done

      echo "[Info] The TCP6 reject rules have been saved in ${WORKING_DIRECTORY}/.tcp6-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp6-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp6-exposures-reject

      # Convert the list of <HOST_IP>:<EXPOSED_PORT> to <HOST_IP> <EXPOSED_PORT_1>[,<EXPOSED_PORT_1>...] format
      for i in $(sed 's#^\[\(.*\)\]:\([0-9]*\)$#\1 \2#g' ${WORKING_DIRECTORY}/.udp6-exposures | group_by_1st_column); do
         
         local dstHost=$(echo "$i" | awk '{print $1}')
         local dstPorts=$(echo "$i" | awk '{print $2}')

         echo "ip6tables -t raw -C PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject
         echo "ip6tables -t raw -A PREROUTING -d $dstHost -p udp -m multiport --dports $dstPorts -m comment --comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject
      done

      echo "[Info] The UDP6 reject rules have been saved in ${WORKING_DIRECTORY}/.udp6-exposures-reject"
   fi
}

#
# [Note] Generate iptables blocking strategy scripts based on port exposure surface file. This function uses ipset to improve performance.
#
get_iptables_reject_rules_from_exposures() {

   local IFS=$'\n'
   local i=

   if [ -f ${WORKING_DIRECTORY}/.tcp4-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      echo "ipset create tcp4-exposures hash:ip,port" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      for i in $(sed 's#:#,tcp:#g' ${WORKING_DIRECTORY}/.tcp4-exposures); do

         echo "ipset add tcp4-exposures $i" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject
      done

      echo "iptables -t raw -C PREROUTING -p tcp -m set --match-set tcp4-exposures dst -m comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      echo "iptables -t raw -I PREROUTING -p tcp -m set --match-set tcp4-exposures dst -m comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      echo "[Info] The TCP4 reject rules have been saved in ${WORKING_DIRECTORY}/.tcp4-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp4-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp4-exposures-reject

      echo "ipset create udp4-exposures hash:ip,port" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject

      for i in $(sed 's#:#,udp:#g' ${WORKING_DIRECTORY}/.udp4-exposures); do

         echo "ipset add udp4-exposures $i" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject
      done

      echo "iptables -t raw -C PREROUTING -p udp -m set --match-set udp4-exposures dst -m comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject

      echo "iptables -t raw -I PREROUTING -p udp -m set --match-set udp4-exposures dst -m comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.udp4-exposures-reject

      echo "[Info] The UDP4 reject rules have been saved in ${WORKING_DIRECTORY}/.udp4-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.tcp6-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp6-exposures-reject

      echo "ipset create tcp6-exposures hash:ip,port family inet6" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject

      for i in $(sed 's#^\(.*\):\([0-9]*\)$#\1,tcp:\2#g' ${WORKING_DIRECTORY}/.tcp6-exposures); do

         echo "ipset add tcp6-exposures $i" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject
      done

      echo "ip6tables -t raw -C PREROUTING -p tcp -m set --match-set tcp6-exposures dst -m comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject

      echo "ip6tables -t raw -I PREROUTING -p tcp -m set --match-set tcp6-exposures dst -m comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.tcp6-exposures-reject

      echo "[Info] The TCP6 reject rules have been saved in ${WORKING_DIRECTORY}/.tcp6-exposures-reject"
   fi

   if [ -f ${WORKING_DIRECTORY}/.udp6-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.udp6-exposures-reject

      echo "ipset create udp6-exposures hash:ip,port family inet6" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject

      for i in $(sed 's#^\(.*\):\([0-9]*\)$#\1,udp:\2#g' ${WORKING_DIRECTORY}/.udp6-exposures); do

         echo "ipset add udp6-exposures $i" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject
      done

      echo "ip6tables -t raw -C PREROUTING -p udp -m set --match-set udp6-exposures dst -m comment \"Unified Access Control\" -j DROP || \\" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject

      echo "ip6tables -t raw -I PREROUTING -p udp -m set --match-set udp6-exposures dst -m comment \"Unified Access Control\" -j DROP" >> ${WORKING_DIRECTORY}/.udp6-exposures-reject

      echo "[Info] The UDP6 reject rules have been saved in ${WORKING_DIRECTORY}/.udp6-exposures-reject"
   fi
}

#
# To be verified
#
run_outbound_capture_and_summarize_connections() {

   local connectionSummaryPath="$1"
   local tcpdumpScript="${@:2}"

   if [ -z "$connectionSummaryPath" ] || [ -z "$tcpdumpScript" ]; then
      echo '[Info] Please provide a valid packet capture script.'
      exit -1
   fi

   >$connectionSummaryPath

   eval "$tcpdumpScript" 2>/dev/null | while IFS= read -r line; do
      
      local packet=
      local dstHost=
      local dstPort=

      if [ $(echo "$line" | grep -i -w 'IP' | wc -l) -ne 0 ]; then
         # IPv4 Packets
         packet=$(echo "$line" | awk '{print $3,$5}' | sed 's#^\([0-9.]*\)\.\([0-9]*\)\ \([0-9.]*\)\.\([0-9]*\).*#\1.\2,\3.\4#g')

         # If it is a TCP packet, port detection can be performed on the remote endpoint. If the remote endpoint is in an port open state, it is confirmed as an outbound packet. Otherwise, the remote endpoint may be the initiator of the session. This detection is used to filter out invalid packets, but unavailable for the FTP packets and UDP packets.
         if [ $(echo "$line" | grep -i -w 'tcp' | wc -l) -ne 0 ]; then
            dstHost=$(echo $packet | sed 's#^[0-9.]*\.[0-9]*,\([0-9.]*\)\.\([0-9]*\)$#\1#g')
            dstPort=$(echo $packet | sed 's#^[0-9.]*\.[0-9]*,\([0-9.]*\)\.\([0-9]*\)$#\2#g')
            nc -4nvz -w 2 $dstHost $dstPort 1>/dev/null 2>/dev/null || continue
         fi

         packet=$(echo "$packet" | sed 's#^\([0-9.]*\)\.[0-9]*,\([0-9.]*\)\.\([0-9]*\)$#\1,\2.\3#g')
      elif [ $(echo "$line" | grep -i -w 'IP6' | wc -l) -ne 0 ]; then
         # IPv6 Packets
         # "10:11:20.174380 IP6 2001:db8::1.10884 > 2001:db8::2.10250: tcp 0" → "2001:db8::1,2001:db8::2.10250"
         packet=$(echo "$line" | awk '{print $3,$5}' | sed 's#^\([^.]*\)\.\([0-9]*\)\ \([^.]*\)\.\([0-9]*\).*#\1.\2,\3.\4#g')

         if [ $(echo "$line" | grep -i -w 'tcp' | wc -l) -ne 0 ]; then
            dstHost=$(echo $packet | sed 's#^[^.]*\.[0-9]*,\([^.]*\)\.\([0-9]*\)$#\1#g')
            dstPort=$(echo $packet | sed 's#^[^.]*\.[0-9]*,\([^.]*\)\.\([0-9]*\)$#\2#g')
            nc -6nvz -w 2 $dstHost $dstPort 1>/dev/null 2>/dev/null || continue
         fi

         packet=$(echo "$packet" | sed 's#^\([^.]*\)\.[0-9]*,\([^.]*\)\.\([0-9]*\)$#\1,\2.\3#g')
      fi

      if [ $(echo "$packet" | grep "^$" | wc -l) -ne 0 ]; then
         # Check Empty lines
         continue
      fi

      # Add parameter FX to avoid partial content matching
      if [ $(grep -Fx $packet $connectionSummaryPath | wc -l) -eq 0 ]; then
         echo $packet >> $connectionSummaryPath
      fi
   done

   echo "[Info] The packets have been summarized into file $connectionSummaryPath"
}

#
# [Note] Capture outbound TCP/UDP packets
#
concurrently_run_outbound_captures() {

   load_external_interfaces_from_file
   load_external_ip_addresses_from_file
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_service_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file
   load_k8s_nodes_ip_addresses_from_file

   if [ ${#EXTERNAL_IPV4_ADDRESSES[@]} -ne 0 ]; then

      # Source filtering conditions. The filtering conditions at the source should try to avoid listening ports as much as possible, otherwise it will cause the session direction to be reversed, resulting in the capture of inbound traffic. Of course, there may also be occasional situations where the listening port is allocated as the source port. In cases where the number of listening ports is large, some outbound traffic may be lost. However, as it is traffic collection, the lost traffic in cases where the collection time is long will not affect the final result unless it is explicitly designated that the listening port is used as the source port. Our principle is to discard 1000 correct ones rather than include one incorrect one.
      local srcTcp4Filter=
      local srcUdp4Filter=

      if [ ! -f ${WORKING_DIRECTORY}/.tcp4-exposures ]; then
         echo "[Warn] As tcpdump cannot determine the initiator and receiver of a session in a packet, it is strongly recommended to first obtain the TCP4 exposed surface which will be saved in ${WORKING_DIRECTORY}/.tcp4-exposures to ensure that the initiator ports are not listening ports of current host. If you don't do this, it will lead to overly loose constraints and may result in capturing inbound traffic."
         read -r -p "Continue to do this? [y/n] " input
         input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
         if [ "$input" == "y" ] || [ "$input" == "yes" ]; then
            srcTcp4Filter="$(echo ${EXTERNAL_IPV4_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#src host #g' | sed ':a;N;s/\n/ or /;ba')"
            echo "[Warn] We will use external IP as filtering condition: $srcTcp4Filter"
         else
            exit 0
         fi
      else
         srcTcp4Filter=$(sed 's#:# #g' ${WORKING_DIRECTORY}/.tcp4-exposures | group_by_1st_column_no_limit | awk '{print "src host "$1" and not src port "$2}' | sed 's#,# and not src port #g' | sed ':a;N;$!ba;s/\n/ or /g')
      fi

      if [ ! -f ${WORKING_DIRECTORY}/.udp4-exposures ]; then
         echo "[Warn] As tcpdump cannot determine the initiator and receiver of a session in a packet, it is strongly recommended to first obtain the UDP4 exposed surface which will be saved in ${WORKING_DIRECTORY}/.udp4-exposures to ensure that the initiator ports are not listening ports of current host. If you don't do this, it will lead to overly loose constraints and may result in capturing inbound traffic."
         read -r -p "Continue to do this? [y/n] " input
         input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
         if [ "$input" == "y" ] || [ "$input" == "yes" ]; then
            srcUdp4Filter="$(echo ${EXTERNAL_IPV4_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#src host #g' | sed ':a;N;s/\n/ or /;ba')"
            echo "[Warn] We will use external IP as filtering condition: $srcUdp4Filter"
         else
            exit 0
         fi
      else
         srcUdp4Filter=$(sed 's#:# #g' ${WORKING_DIRECTORY}/.udp4-exposures | group_by_1st_column_no_limit | awk '{print "src host "$1" and not src port "$2}' | sed 's#,# and not src port #g' | sed ':a;N;$!ba;s/\n/ or /g')
      fi

      # Destination filtering conditions. The destination needs to filter out the private network of the node, which is not distinguished in TCP/UDP protocol.
      local dstIpv4Filter=
      for subnet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${K8S_NODES_IPV4_SUBNETS[@]} ${LOOPBACK_SUBNETS_IPV4}; do
         dstIpv4Filter="$dstIpv4Filter and not dst net $subnet"
      done

      echo "ip and tcp and ( $srcTcp4Filter )$dstIpv4Filter" > ${WORKING_DIRECTORY}/.tcp4-outbound-packets-filter
      echo "ip and udp and ( $srcUdp4Filter )$dstIpv4Filter" > ${WORKING_DIRECTORY}/.udp4-outbound-packets-filter
   fi

   if [ ${#EXTERNAL_IPV6_ADDRESSES[@]} -ne 0 ]; then
      
      local srcTcp6Filter=
      local srcUdp6Filter=

      if [ ! -f ${WORKING_DIRECTORY}/.tcp6-exposures ]; then
         echo "[Warn] As tcpdump cannot determine the initiator and receiver of a session in a packet, it is strongly recommended to first obtain the TCP4 exposed surface which will be saved in ${WORKING_DIRECTORY}/.tcp6-exposures to ensure that the initiator ports are not listening ports of current host. If you don't do this, it will lead to overly loose constraints and may result in capturing inbound traffic."
         read -r -p "Continue to do this? [y/n] " input
         input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
         if [ "$input" == "y" ] || [ "$input" == "yes" ]; then
            srcTcp6Filter="$(echo ${EXTERNAL_IPV6_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#src host #g' | sed ':a;N;s/\n/ or /;ba')"
            echo "[Warn] We will use external IP as filtering condition: $srcTcp6Filter"
         else
            exit 0
         fi
      else
         srcTcp6Filter=$(sed 's#:# #g' ${WORKING_DIRECTORY}/.tcp6-exposures | group_by_1st_column_no_limit | awk '{print "src host "$1" and not src port "$2}' | sed 's#,# and not src port #g' | sed ':a;N;$!ba;s/\n/ or /g')
      fi

      if [ ! -f ${WORKING_DIRECTORY}/.udp6-exposures ]; then
         echo "[Warn] As tcpdump cannot determine the initiator and receiver of a session in a packet, it is strongly recommended to first obtain the UDP4 exposed surface which will be saved in ${WORKING_DIRECTORY}/.udp6-exposures to ensure that the initiator ports are not listening ports of current host. If you don't do this, it will lead to overly loose constraints and may result in capturing inbound traffic."
         read -r -p "Continue to do this? [y/n] " input
         input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
         if [ "$input" == "y" ] || [ "$input" == "yes" ]; then
            srcUdp6Filter="$(echo ${EXTERNAL_IPV6_ADDRESSES[@]} | tr ' ' '\n' | sed 's#^#src host #g' | sed ':a;N;s/\n/ or /;ba')"
            echo "[Warn] We will use external IP as filtering condition: $srcUdp6Filter"
         else
            exit 0
         fi
      else
         srcUdp6Filter=$(sed 's#:# #g' ${WORKING_DIRECTORY}/.udp6-exposures | group_by_1st_column_no_limit | awk '{print "src host "$1" and not src port "$2}' | sed 's#,# and not src port #g' | sed ':a;N;$!ba;s/\n/ or /g')
      fi

      # Destination filtering conditions. The destination needs to filter out the private network of the node, which is not distinguished in TCP/UDP protocol.
      local dstIpv6Filter=
      for subnet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${K8S_NODES_IPV6_SUBNETS[@]} ${LOOPBACK_SUBNETS_IPV6}; do
         dstIpv6Filter="$dstIpv6Filter and not dst net $subnet"
      done

      echo "ip and tcp and ( $srcTcp6Filter )$dstIpv6Filter" > ${WORKING_DIRECTORY}/.tcp6-outbound-packets-filter
      echo "ip and udp and ( $srcUdp6Filter )$dstIpv6Filter" > ${WORKING_DIRECTORY}/.udp6-outbound-packets-filter
   fi

   local i=

   for i in ${EXTERNAL_INTERFACES[@]}; do

      if [ -f ${WORKING_DIRECTORY}/.tcp4-outbound-packets-filter ]; then
         nohup $0 --run-outbound-capture-and-summarize-connections "${WORKING_DIRECTORY}/.tcp4-outbound-connections-summary timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp4-outbound-packets-filter" &
      fi

      if [ -f ${WORKING_DIRECTORY}/.udp4-outbound-packets-filter ]; then
         nohup $0 --run-outbound-capture-and-summarize-connections "${WORKING_DIRECTORY}/.udp4-outbound-connections-summary timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp4-outbound-packets-filter" &
      fi

      if [ -f ${WORKING_DIRECTORY}/.tcp6-outbound-packets-filter ]; then
         nohup $0 --run-outbound-capture-and-summarize-connections "${WORKING_DIRECTORY}/.tcp6-outbound-connections-summary timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp6-outbound-packets-filter" &
      fi

      if [ -f ${WORKING_DIRECTORY}/.udp6-outbound-packets-filter ]; then
         nohup $0 --run-outbound-capture-and-summarize-connections "${WORKING_DIRECTORY}/.udp6-outbound-connections-summary timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp6-outbound-packets-filter" &
      fi
   done

}

#
# [Note] Please use this function on each node of target K8s cluster. Please use merged connection summaries. Please filter out the inner-connections of K8s clusters first. Most of strategies to be migrated are NodePort stategies.
#
run_strategies_migration_verification() {

   load_external_ip_addresses_from_file
   
   local i=
   local j=
   local k=

   # 1. inbound strategies verification
   #  [1] Generate strategies verification table
   if [ -f ${WORKING_DIRECTORY}/.tcp4-connections-summary ]; then
      >${WORKING_DIRECTORY}/.tcp4-connections-verification
   fi

   for i in $(cat ${WORKING_DIRECTORY}/.tcp4-connections-summary); do
      for j in ${EXTERNAL_IPV4_ADDRESSES[@]}; do
         local srcHost=$(echo $i | sed 's#^\([^,]*\),.*#\1#g')
         local dstPort=$(echo $i | sed 's#.*\.\([0-9]*\)$#\1#g')
         k="$srcHost,$j.$dstPort"
         echo "$k" >> ${WORKING_DIRECTORY}/.tcp4-connections-verification
      done
   done

   sort -t',' -k1,1 ${WORKING_DIRECTORY}/.tcp4-connections-verification | tr ',' ' ' | group_by_1st_column | sed 's# # → #g'

   # 2. check port listenings and start nc test pile
   # 3. 
   ${EXTERNAL_IPV4_ADDRESSES}
   
   # outbound strategies verification
}

#
# [Note] Generate Cisco Switch Access Control List Configuration Script
#
generate_cisco_acl_scripts() {

   local connectionSummaryPath=$1
   local protocol=$2
   local protocolType=
   local direction=$3
   local preposition=
   local endpoints=
   local aclScriptFile=$4

   if [ -z "$connectionSummaryPath" ] || [ ! -f "$connectionSummaryPath" ] || [ -s "$connectionSummaryPath" ]; then
      echo '[Warn] Please provide a valid connection summary file path.'
      exit -1
   fi

   if [ -z "$protocol" ] || [ -z "$(echo "$protocol" | grep -i -w -E 'tcp4|udp4|tcp6|udp6')" ]; then
      echo '[Warn] Please provide a valid IP protocol: tcp4, udp4, tcp6 or udp6.'
      exit -1
   fi

   protocolType=$(echo $protocol | tr -d '[:digit:]')

   if [ -z "$direction" ] || [ -z "$(echo "$direction" | grep -i -w -E 'inbound|outbound')" ]; then
      echo '[Warn] Please provide a valid direction: inbound, outbound.'
      exit -1
   fi

   if [ -z "$aclScriptFile" ]; then
      echo '[Warn] Please provide a valid acl script file path (target file).'
      exit -1
   fi

   if [ "$direction" == "outbound" ]; then
      preposition="FROM"
      endpoints=$(awk -F, '{print $1}' $connectionSummaryPath | sort -u | head -1)
   else
      preposition="TO"
      endpoints=$(sed 's#^.*,\(.*\)\.[0-9]*$#\1#g' $connectionSummaryPath | sort -u | head -1)
   fi

   >$aclScriptFile

   echo "ip access-list extended PERMIT_$protocol_$preposition_$endpoints" >> $aclScriptFile
   sed "s#^\([^,]*\),\(.*\)\.\([0-9]*\)$# permit $protocolType host \1 host \2 eq \3#g" $connectionSummaryPath >> $aclScriptFile
   echo >> $aclScriptFile

   echo 'interface GigabitEthernet_/_/_' >> $aclScriptFile
   echo " description Link to Host $endpoints" >> $aclScriptFile
   echo " ip access-group PERMIT_$protocol_$preposition_$endpoints in" >> $aclScriptFile
}

#
# [Note] Generate New H3C Switch Access Control List Configuration Script
#
generate_h3c_acl_scripts() {

   local connectionSummaryPath=$1
   local protocol=$2
   local protocolType=
   local direction=$3
   local preposition=
   local endpoints=
   local aclScriptFile=$4

   if [ -z "$connectionSummaryPath" ] || [ ! -f "$connectionSummaryPath" ] || [ -s "$connectionSummaryPath" ]; then
      echo '[Warn] Please provide a valid connection summary file path.'
      exit -1
   fi

   if [ -z "$protocol" ] || [ -z "$(echo "$protocol" | grep -i -w -E 'tcp4|udp4|tcp6|udp6')" ]; then
      echo '[Warn] Please provide a valid IP protocol: tcp4, udp4, tcp6 or udp6.'
      exit -1
   fi

   if [ -z "$direction" ] || [ -z "$(echo "$direction" | grep -i -w -E 'inbound|outbound')" ]; then
      echo '[Warn] Please provide a valid direction: inbound, outbound.'
      exit -1
   fi

   if [ -z "$aclScriptFile" ]; then
      echo '[Warn] Please provide a valid acl script file path (target file).'
      exit -1
   fi

   if [ "$direction" == "outbound" ]; then
      preposition="FROM"
      endpoints=$(awk -F, '{print $1}' $connectionSummaryPath | sort -u | head -1)
   else
      preposition="TO"
      endpoints=$(sed 's#^.*,\(.*\)\.[0-9]*$#\1#g' $connectionSummaryPath | sort -u | head -1)
   fi

   >$aclScriptFile

   local aclNumber=$(( RANDOM % 8001 + 1000 ))
   local ruleId=5
   local srcHost=
   local dstHost=
   local dstPort=

   echo "system-view" >> $aclScriptFile
   echo "acl number $aclNumber" >> $aclScriptFile

   for i in $(cat $connectionSummaryPath); do
      srcHost=$(echo "$i" | sed 's#^\([^,]*\),[^,]*\.[0-9]*$#\1#g')
      dstHost=$(echo "$i" | sed 's#^[^,]*,\([^,]*\)\.[0-9]*$#\1#g')
      dstPort=$(echo "$i" | sed 's#^[^,]*,[^,]*\.\([0-9]*\)$#\1#g')

      echo " rule $ruleId permit $protocolType source $srcHost 0 destination $dstHost 0 destination-port eq $dstPort" >> $aclScriptFile
      acl=$(expr $acl + 5)
   done

   echo "quit" >> $aclScriptFile

   # Configure stream classifier
   echo "traffic classifier CLASSIFIER_$endpoints" >> $aclScriptFile
   echo " if-match acl $aclNumber" >> $aclScriptFile
   echo "quit" >> $aclScriptFile

   # Configure stream behaviour
   echo "traffic behavior BEHAVIOR_$endpoints" >> $aclScriptFile
   echo " permit" >> $aclScriptFile
   echo "quit" >> $aclScriptFile

   # Create stream strategy
   echo "traffic policy POLICY_$endpoints" >> $aclScriptFile
   echo " classifier CLASSIFIER_$endpoints behavior BEHAVIOR_$endpoints" >> $aclScriptFile
   echo "quit" >> $aclScriptFile

   echo "interface GigabitEthernet_/_/_" >> $aclScriptFile # Please replace with the actual interface
   echo " traffic-policy POLICY_$endpoints $direction" >> $aclScriptFile
   echo "quit" >> $aclScriptFile
}

translate_connections_summary_with_cmdb() {
   :
}

#
# [Note] Analyzing non TCP/UDP protocols, data packets of such protocols should be released on the migration destination switch.
#
capture_non_tcp_udp_packets() {

   load_external_interfaces_from_file
   load_external_ip_addresses_from_file
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_service_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file

   local subnet=
   local ipv4Subnets=
   local ipv6Subnets=

   for subnet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${LOOPBACK_SUBNETS_IPV4}; do
      ipv4Subnets="$ipv4Subnets and not net $subnet"
   done

   for subnet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${LOOPBACK_SUBNETS_IPV6}; do
      ipv6Subnets="$ipv6Subnets and not net $subnet"
   done

   echo "ip and not tcp and not udp$ipv4Subnets or ip6 and not tcp and not udp$ipv6Subnets" > ${WORKING_DIRECTORY}/.non-tcp-udp-packets-filter

   touch ${WORKING_DIRECTORY}/.non-tcp-udp-connections-summary

   echo '[Info] Please wait for the packet capture to be completed ...'

   timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i any -lqnn -F ${WORKING_DIRECTORY}/.non-tcp-udp-packets-filter 2>/dev/null | while IFS= read -r line; do
      
      if [ $(echo "$line" | grep -i -w 'IP' | wc -l) -ne 0 ]; then
         # IPv4 Packets
         # [Example] 134.80.135.43 134.80.135.45: VRRPv2
         packet=$(echo "$line" | awk '{print $3","$5","$6}')
      elif [ $(echo "$line" | grep -i -w 'IP6' | wc -l) -ne 0 ]; then
         # IPv6 Packets
         packet=$(echo "$line" | awk '{print $3","$5","$6}')
      fi

      if [ $(echo "$packet" | grep "^$" | wc -l) -ne 0 ]; then
         # Check Empty lines
         continue
      fi

      # Add parameter FX to avoid partial content matching
      if [ $(grep -Fx $packet ${WORKING_DIRECTORY}/.non-tcp-udp-connections-summary | wc -l) -eq 0 ]; then
         echo $packet >> ${WORKING_DIRECTORY}/.non-tcp-udp-connections-summary
      fi
   done

   echo "[Info] The packets have been summarized into file ${WORKING_DIRECTORY}/.non-tcp-udp-connections-summary"
}

#
# Not implemented
#
capture_invalid_rst_packets() {
   tcpdump -i any -nn 'tcp[tcpflags] & tcp-rst != 0'
}


orderedPara=(
   "--batch-remote-deliver"
   "--batch-remote-execute"
   "--dump-dnat-strategy-tables"
   "--concurrent-process-dnat-exposures"
   "--show-dnat-exposures-perspective"
   "--dump-listening-tables"
   "--sequential-process-listening-exposures"
   "--concurrent-process-listening-exposures"
   "--merge-exposures"
   "--get-packets-filter-file-by-exposures"
   "--get-packets-capture-script"
   "--run-capture-and-summarize-connections"
   "--concurrently-run-packets-captures"
   "--preventive-iptables-allow-rules"
   "--get-iptables-allow-rules-from-connections-summary"
   "--get-iptables-reject-rules-from-exposures"
   "--run-outbound-capture-and-summarize-connections"
   "--concurrently-run-outbound-captures"
   "--capture-non-tcp-udp-packets"
   "--generate-cisco-acl-scripts"
   "--generate-h3c-acl-scripts"
   "--usage"
   "--help"
   "--manual"
)

#
# Maps between shell options and functions
#
declare -A mapParaFunc=(
   ["--batch-remote-deliver"]="batch_remote_deliver"
   ["--batch-remote-execute"]="batch_remote_execute"
   ["--dump-dnat-strategy-tables"]="dump_dnat_strategy_tables"
   ["--concurrent-process-dnat-exposures"]="concurrent_process_dnat_exposures"
   ["--show-dnat-exposures-perspective"]="show_dnat_exposures_perspective"
   ["--dump-listening-tables"]="dump_listening_tables"
   ["--sequential-process-listening-exposures"]="sequential_process_listening_exposures"
   ["--concurrent-process-listening-exposures"]="concurrent_process_listening_exposures"
   ["--merge-exposures"]="merge_exposures"
   ["--get-packets-filter-file-by-exposures"]="get_packets_filter_file_by_exposures"
   ["--get-packets-capture-script"]="get_packets_capture_script"
   ["--run-capture-and-summarize-connections"]="run_capture_and_summarize_connections"
   ["--concurrently-run-packets-captures"]="concurrently_run_packets_captures"
   ["--preventive-iptables-allow-rules"]="preventive_iptables_allow_rules"
   ["--get-iptables-allow-rules-from-connections-summary"]="get_iptables_allow_rules_from_connections_summary"
   ["--get-iptables-reject-rules-from-exposures"]="get_iptables_reject_rules_from_exposures"
   ["--run-outbound-capture-and-summarize-connections"]="run_outbound_capture_and_summarize_connections"
   ["--concurrently-run-outbound-captures"]="concurrently_run_outbound_captures"
   ["--capture-non-tcp-udp-packets"]="capture_non_tcp_udp_packets"
   ["--generate-cisco-acl-scripts"]="generate_cisco_acl_scripts"
   ["--generate-h3c-acl-scripts"]="generate_h3c_acl_scripts"
   ["--usage"]="usage"
   ["--help"]="usage"
   ["--manual"]="usage"
)

#
# Maps between shell options and specifications
#
declare -A mapParaSpec=(
   ["--batch-remote-deliver"]="Batchly push specified files to remote nodes."
   ["--batch-remote-execute"]="Batchly execute some commands on remote nodes."
   ["--dump-dnat-strategy-tables"]="Query iptables DNAT strategies and save them in hidden files."
   ["--concurrent-process-dnat-exposures"]="Concurrently process iptables DNAT strategites and save them in original hidden files."
   ["--show-dnat-exposures-perspective"]="Tracking the exposed forwarding surface of iptables NAT through linked lists."
   ["--dump-listening-tables"]="Retrieve the port listening list and export it to hidden files. These hidden files are distinguished by IP address family and TCP/UDP protocols."
   ["--sequential-process-listening-exposures"]="Process the port listening list sequentially in a separate process, filtering out non exposed listening surfaces."
   ["--concurrent-process-listening-exposures"]="Multi process concurrent processing port listening list, filtering out non exposed surface listening."
   ["--merge-exposures"]="Merge the exposed surfaces of iptables DNAT and port listening into a unified exposed surface"
   ["--get-packets-filter-file-by-exposures"]="Generate packet capture filter files based on address family and protocol type."
   ["--get-packets-capture-script"]="Generate packet capture scripts and save them in a hidden file."
   ["--run-capture-and-summarize-connections"]="Independently execute a packet capture script and organize the data packet into a connection summary file."
   ["--concurrently-run-packets-captures"]="Read packet capture commands from the packet capture script file and execute each command in the background."
   ["--preventive-iptables-allow-rules"]="Advance policy deployment of the private network of the current node to avoid connection failure after subsequent security reinforcement."
   ["--get-iptables-allow-rules-from-connections-summary"]="Generate a network policy release script based on network connection summary data."
   ["--get-iptables-reject-rules-from-exposures"]="Generate Iptables packet dropout strategy script based on TCP4/6 and UDP4/6 port exposures data."
   ["--run-outbound-capture-and-summarize-connections"]="Execute a single outbound packet capture task, during which a connection summary will be output."
   ["--concurrently-run-outbound-captures"]="Concurrent launch of outbound packet capture task."
   ["--capture-non-tcp-udp-packets"]="Capture non TCP and non UDP packets."
   ["--generate-cisco-acl-scripts"]="Generate CISCO switch ACL configuration scripts. <usage> $0 --generate-cisco-acl-scripts <conn-summary-file> <tcp4/6|udp4/6> <inbound|outbound> <target-file>"
   ["--generate-h3c-acl-scripts"]="Generate H3C switch ACL configuration scripts. <usage> $0 --generate-h3c-acl-scripts <conn-summary-file> <tcp4/6|udp4/6> <inbound|outbound> <target-file>"
   ["--usage"]="Simplified operation manual."
   ["--help"]="Simplified operation manual."
   ["--manual"]="Simplified operation manual."
)

usage() {
   echo 'Network Strategy Convergence and Blocking Tools [v251221]'
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