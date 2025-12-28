###################################
# IPTABLES BLOCKER       v251221  #
# paragon.cmcc.com                #
###################################

#!/bin/bash

# [Note] working principle: Capture Data Packets → Generate iptables blocking execution plan → Implement blockage

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
# [9] The local link addresses 127.0.0.0/8 and fe80::/10 are both loopback address networks, and traffic passing through these addresses should be filtered
# [10] Interpretability of IP quintuple data;
# [11] iptables -t raw -I PREROUTING -p tcp -s 2001:db8:abc1::/64 -j ACCEPT # Standalone docker policies 
# [12] The blocking of IPv6 addresses requires the use of the ip6tables command.
# [13] The function of automatically revoking blockage within 5 minutes;
# [14] Add comment to all generated strategies.
# [15] netstat -anltp needs to be replaced with ss -nltp to improve the query efficiency and accuracy of the listening ports
# [16] External IP is based on existing generation logic, with nodeport port listening and nodeport iptables (newer k8s version)

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

if [ -z "$(which jq 2>/dev/null)" ] && [ -z "$(alias jq 2>/dev/null)" ]; then
   echo '[Warn] jq is not installed yet.'
   exit -1
fi

if [ -z "$(which yq 2>/dev/null)" ] && [ -z "$(alias yq 2>/dev/null)" ]; then
   echo '[Warn] yq is not installed yet.'
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

pip2 show ipaddress -q 2>/dev/null
if [ $? -ne 0 ]; then
   pip2 install ipaddress-1.0.23-py2.py3-none-any.whl -q 2>/dev/null
   exit -1
fi

if [ -z "$(which kubectl 2>/dev/null)" ] && [ -z "$(alias kubectl 2>/dev/null)" ]; then
   echo '[Warn] The current script depends on running on a node that deploys kubectl and has administrative privileges on the K8s cluster.'
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
LOOPBACK_SUBNETS_IPV4=127.0.0.1/8
LOOPBACK_SUBNETS_IPV6=::1/128

PREFER_IPV6=false

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

load_docker_subnet_addresses_from_file() {

   if [ ! -f ${WORKING_DIRECTORY}/.docker-networks ]; then
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
      ${WORKING_DIRECTORY}/network-utilities.sh --get-service-cidr
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
         }
         
         if (count > 0) {
            print key " " result
         }
      }
   }'
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
      exit -1
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
      exit -1
   fi
   
   /usr/bin/mv -f $temporaryFilePath $originalFilePath
}

# 定义全局变量,标识k8s集群nodePort类型的service的端口号是否能被netstat检查到
# k8s_svc_nodeport_can_be_seen_netstat=false

#########################################
# 用于封堵panji名称空间端口用到的变量      #
#########################################

# 全局变量：存储暴露的端口数组
# pj_port=(53 5473 6666 9153 9999 22365)

# 预先定义需要查询的命名空间,如果磐基名称空间有变化，可以手动修改维护这个名称空间数组
# namespaces=("chaosblade" "default" "istio-system" "kube-node-lease" "kube-public" "kube-system" "monitor-ns" "nfs-provisioner-ns" "paas-admin" "paas-ec" "paas-middleware" "paas-monitor" "paas-public")

# 输出文件路径
# pj_output_file="pj-port-svc-mapper.txt"

# 定义布尔变量，初始值为假,如果传入的参数指明只封堵磐基名称空间的端口，这个变量就为true
# Block_only_panji=false

# 查找指定命名空间中暴露在宿主机的端口及对应服务关系
# 结果会赋值给全局变量 pj_port

# k8s svc nodePort类型的端口，如果通过netstat 找不到，需要用到的全局变量：存储所有命名空间暴露的宿主机端口（去重排序后）
# all_ns_port=(53 5473 6666 9153 22365)
# 定义输出文件路径（可根据需求修改）
# output_file="./k8s_exposed_ports_mapping.txt"

# 函数：收集所有命名空间的暴露端口（NodePort/HostPort/HostNetwork）
# find_all_ns_exposed_host_ports_with_mapping() {
#     local ports=()

#     # 1. 清空历史输出文件（若文件存在）
#     > "$output_file"
#     echo "暴露端口映射关系记录文件：$output_file"
#     echo "======================================" >> "$output_file"

#     # 2. 获取集群中所有命名空间（排除因权限等问题无法访问的命名空间）
#     echo "正在获取集群所有命名空间..."
#     local all_namespaces
#     all_namespaces=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)

#     # 检查是否获取到命名空间（避免kubectl未就绪或权限不足）
#     if [ -z "$all_namespaces" ]; then
#         echo "警告：未获取到任何命名空间（可能kubectl未配置或权限不足）"
#         return 1
#     fi

#     # 3. 遍历所有命名空间处理暴露端口
#     while IFS= read -r ns; do
#         echo "正在处理命名空间: $ns"
#         echo -e "\n--- 命名空间: $ns ---" >> "$output_file"

#         # 3.1 处理 NodePort 类型 Service（记录Service名称和端口映射）
#         local node_port_data
#         # 通过jsonpath提取Service名称、NodePort、端口名称（仅筛选NodePort类型）
#         node_port_data=$(kubectl get svc -n "$ns" -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"|"}{.spec.ports[0].nodePort}{"|"}{.spec.ports[0].name}{"\n"}{end}' 2>/dev/null)
        
#         while IFS="|" read -r svc_name node_port port_name; do
#             # 过滤空值（避免jsonpath提取时的空行或无效数据）
#             if [ -n "$node_port" ] && [ -n "$svc_name" ]; then
#                 ports+=("$node_port")
#                 # 写入映射关系：类型|宿主机端口|资源标识（Service/命名空间/名称:端口名）
#                 echo "NodePort|$node_port|svc/$ns/$svc_name:$port_name" >> "$output_file"
#             fi
#         done <<< "$node_port_data"

#         # 3.2 处理 Pod 中的 HostPort（记录容器名称和端口映射）
#         local host_port_data
#         # 提取Pod名称、容器名称、HostPort、容器端口（仅筛选有hostPort的端口）
#         host_port_data=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.containers[*]}{.name}{"|"}{.ports[?(@.hostPort)].hostPort}{"|"}{.ports[?(@.hostPort)].containerPort}{"\n"}{end}{end}' 2>/dev/null)
        
#         while IFS="|" read -r pod_name container_name host_port container_port; do
#             if [ -n "$host_port" ] && [ -n "$container_name" ]; then
#                 ports+=("$host_port")
#                 # 写入映射关系：类型|宿主机端口|资源标识（Pod/命名空间/容器名:容器端口）
#                 echo "HostPort|$host_port|pod/$ns/$container_name:$container_port" >> "$output_file"
#             fi
#         done <<< "$host_port_data"

#         # 3.3 处理 HostNetwork=true 的 Pod（使用容器端口作为宿主机暴露端口）
#         local host_network_data
#         # 提取Pod名称、容器名称、容器端口（仅筛选hostNetwork=true的Pod）
#         host_network_data=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.name}{"|"}{range .spec.containers[*]}{.name}{"|"}{.ports[*].containerPort}{"\n"}{end}{end}' 2>/dev/null)
        
#         while IFS="|" read -r pod_name container_name container_port; do
#             # 处理多个容器端口（若容器暴露多个端口，会以空格分隔，需拆分）
#             for port in $container_port; do
#                 if [ -n "$port" ] && [ -n "$container_name" ]; then
#                     ports+=("$port")
#                     # 写入映射关系：类型|宿主机端口|资源标识（HostNetwork/命名空间/容器名:容器端口）
#                     echo "HostNetwork|$port|hostNetwork/$ns/$container_name:$port" >> "$output_file"
#                 fi
#             done
#         done <<< "$host_network_data"

#     done <<< "$all_namespaces"

#     # 4. 对收集的端口去重、按数字升序排序，赋值给全局变量 all_ns_port
#     if [ ${#ports[@]} -gt 0 ]; then
#        echo "端口数组的元素（逐行输出）："
#        # 方式1：for in 遍历数组（推荐，兼容性好）
#        for port in "${ports[@]}"; do
#            echo "$port"
#        done
       
#        echo "---------------------------" 
#        all_ns_port=($(printf "%s\n" "${ports[@]}" | sort -n | uniq))	
#        for port in "${all_ns_port[@]}"; do
#            echo "$port"
#        done

#         all_ns_port=($(printf "%s\n" "${all_ns_port[@]}" | sort -n | uniq))
#         echo -e "\n所有命名空间暴露的宿主机端口（去重排序后）：${all_ns_port[*]}"
#         echo -e "\n======================================" >> "$output_file"
#         echo -e "\n所有命名空间暴露的宿主机端口（去重排序后）：${all_ns_port[*]}">>"$output_file"
#         echo "总计暴露端口数（去重后）：${#all_ns_port[@]}" >> "$output_file"
#     else
#         echo -e "\n未收集到任何暴露的宿主机端口"
#         echo -e "\n======================================" >> "$output_file"
#         echo "未收集到任何暴露的宿主机端口" >> "$output_file"
#     fi
    
#         echo "all_ns_port is "$all_ns_port >>tcpdump.log
# 	perl -p -i -e "s#^all_ns_port=.*#all_ns_port=(${all_ns_port[*]})#g" $0

# }

# find_exposed_host_ports_with_mapping() {
#     # 检查kubectl命令是否存在
#     if ! command -v kubectl &> /dev/null; then
#         echo "未检测到kubectl命令，直接返回，不修改全局变量"
#         return  # 直接返回，不修改全局变量
#     fi
    
#     local ports=()

#     # 清空历史文件
#     > "$pj_output_file"

#     # 遍历panji使用的命名空间
#     for ns in "${namespaces[@]}"; do
#         echo "正在处理命名空间: $ns"
        
#         # 1. 处理NodePort类型的Service（记录Service名称和端口映射）
#         local node_port_data
#         node_port_data=$(kubectl get svc -n "$ns" -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"|"}{.spec.ports[*].nodePort}{"|"}{.spec.ports[*].name}{"\n"}{end}')
#         while IFS="|" read -r svc_name node_port port_name; do
#             if [ -n "$node_port" ] && [ -n "$svc_name" ]; then
#                 ports+=("$node_port")
#                 echo "NodePort|$node_port|svc/$ns/$svc_name:$port_name" >> "$pj_output_file"
#             fi
#         done <<< "$node_port_data"

#         # 2. 处理Pod中的hostPort（记录容器名称）
#         local host_port_data
#         host_port_data=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.containers[*]}{.name}{"|"}{.ports[?(@.hostPort)].hostPort}{"|"}{.ports[?(@.hostPort)].containerPort}{"\n"}{end}{end}')
#         while IFS="|" read -r pod_name container_name host_port container_port; do
#             if [ -n "$host_port" ] && [ -n "$container_name" ]; then
#                 ports+=("$host_port")
#                 echo "HostPort|$host_port|pod/$ns/$container_name:$container_port" >> "$pj_output_file"
#             fi
#         done <<< "$host_port_data"

#         # 3. 处理hostNetwork=true的Pod（使用容器端口作为暴露端口）
#         local host_network_data
#         host_network_data=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.name}{"|"}{range .spec.containers[*]}{.name}{"|"}{.ports[*].containerPort}{"\n"}{end}{end}')
#         while IFS="|" read -r pod_name container_name container_port; do
#             if [ -n "$container_port" ] && [ -n "$container_name" ]; then
#                 ports+=("$container_port")
#                 echo "HostNetwork|$container_port|hostNetwork/$ns/$container_name:$container_port" >> "$pj_output_file"
#             fi
#         done <<< "$host_network_data"
#     done

#     # 对端口去重并排序，赋值给全局变量
#     pj_port=($(printf "%s\n" "${ports[@]}" | sort -n | uniq))
#     # 将数组元素通过换行符分隔，排序后去重，再转回数组
#     pj_port=($(printf "%s\n" "${pj_port[@]}" | sort -n | uniq))
#     perl -p -i -e "s#^pj_port=.*#pj_port=(${pj_port[*]})#g" $0
# }
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
# get_nodes() {

#    # The IP of all nodes obtained online
#    local onlineNodes=($(kubectl get node --request-timeout=8s -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address' | sort -u))

#    # Overwrite local persistent deployment data with dynamically obtained data
#    set_list_vals "nodes" "${onlineNodes[@]}"
# }

#
# 3. Get the IP of current node
#
# get_curr_node_ip() {

#    # Remove the previous settings
#    currNodeIP=
#    perl -p -i -e 's/^currNodeIP=.*/currNodeIP=/g' $0

#    # Obtain K8s cluster nodes' IP
#    get_nodes

#    if [ ${#nodes[@]} -eq 0 ]; then
#       exit 1
#    fi

#    # Obtain all IPs of all interfaces
#    local ipArr=(`ip a | grep inet | grep -E -o '([0-9a-fA-F:]+)/[0-9]{1,3}|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -F'/' '{print $1}' | grep -vE '127.0.0.1|::1' | sort | uniq`)

#    if [ ${#ipArr[@]} -eq 0 ]; then
#       echo '[Warn] Cannot obtain the IPs of all interfaces!'
#       exit 1
#    fi

#    # Solving the intersection of K8s cluster node IP and current node interface IP
#    local intersect=(`echo ${nodes[*]} ${ipArr[*]} | sed 's/ /\n/g' | sort | uniq -c | awk '$1!=1{print $2}'`)

#    if [ ${#intersect[@]} -gt 1 ]; then
#       echo '[Warn] A node should not have more than 1 K8s cluster node IPs!'
#       exit 1
#    elif [ ${#intersect[@]} -eq 0 ]; then
#       echo '[Warn] Although the current node has K8s management permissions, it does not belong to the K8s node.'
#       exit 1
#    fi

#    currNodeIP=${intersect[@]:0:1}
#    perl -p -i -e "s/^currNodeIP=.*/currNodeIP=$currNodeIP/g" $0
# }

#
# 3. Obtain IP addresses of effective network interfaces
#
# get_host_ip_arr() {

#    # The expression of ignored interface names
#    local expIfNames=`echo ${ignIfNames[@]} | sed 's/ /|/g'`

#    # The effective interface names
#    local effIfNames=(`ip link show | grep -E '^[0-9]+:' | sed 's/^[0-9^\ ]*: \(.*\):.*/\1/g' | grep -vE $expIfNames`)

#    local arrIpLocal=()
#    for ifName in ${effIfNames[@]}; do
#       arrIpLocal+=(`ip address show $ifName | grep inet | grep -E -o '([0-9a-fA-F:]+)/[0-9]{1,3}|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -F'/' '{print $1}' | grep -vE '127.0.0.1|::1' | sort | uniq`)
#    done

#    echo ${arrIpLocal[@]}
# }

#
# 4. Obtain the pods CIDR through calico-node yamls
#
# get_pod_cidr() {
   
#     # 检查kubectl命令是否存在,如果是普通节点上没有kubectl命令，无法获取，直接复用master节点上的识别结果
#     if ! command -v kubectl &> /dev/null; then
#         echo "kubectl command not found, skipping pod CIDR initialization"
#         return 0  # 命令不存在，不执行后续操作
#     fi

#    podCidr=`kubectl get ds calico-node -n kube-system --request-timeout=8s -o json 2>/dev/null | jq -r -c '.spec.template.spec.containers[].env[]|select(.name=="CALICO_IPV4POOL_CIDR")|.value' | head -1`

#    # 判断变量是否为空（包括空字符串或null）
# if [ -z "$podCidr" ] || [ "$podCidr" = "null" ]; then
#     # 如果为空，则执行第二个命令获取值
#     podCidr=$(kubectl get ippool default-ipv4-ippool -o yaml 2>/dev/null | grep -i cidr | awk -F: '{print $2}' | tr -d '[:space:]')
# fi
#     echo "podCidr is "$podCidr >>tcpdump.log
#    perl -p -i -e "s#^podCidr=.*#podCidr=$podCidr#g" $0
# }


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

   if [ -z "$filePath" ] || [ -z "$beginLineNo" ] || [ -z "$endLineNo" ]; then
      echo '[Warn] This function need 3 parameters: the iptables strategies file path, the begin line number and the end line number of this file.'
      exit -1
   fi

   for k in $(sed -n "$beginLineNo,$endLineNo"p $filePath); do

      local listenHost=$(echo "$k" | awk '{print $1}' | sed 's#^\(.*\):[0-9]*$#\1#g')
      local listenPort=$(echo "$k" | awk '{print $1}' | sed 's#^.*:\([0-9]*\)$#\1#g')
      if $(check_if_subnet_in_exposure "$listenHost"); then
         if [ "$listenHost" == "*" ]; then
            # The asterisk means listening on both IPv4 and IPv6 wildcard addresses simultaneously. Therefore, it is expanded into two listening records.
            local remoteHost=$(echo "$k" | awk '{print $2}')
            local note=$(echo "$k" | awk '{print $3}')
            echo "0.0.0.0:$listenPort $remoteHost $note" >> $temporaryFilePath_IPv4
            echo "[::]:$listenPort $remoteHost $note" >> $temporaryFilePath_IPv6
         else
            echo $k >> $temporaryFilePath
         fi
      fi
   done
}

dump_listening_tables() {

   load_external_ip_addresses_from_file

   # Reset TCP/UDP listening exposures raw file
   >${WORKING_DIRECTORY}/.tcp4-listening-exposures
   >${WORKING_DIRECTORY}/.tcp6-listening-exposures
   >${WORKING_DIRECTORY}/.udp4-listening-exposures
   >${WORKING_DIRECTORY}/.udp6-listening-exposures

   if [ ${#EXTERNAL_IPV4_ADDRESSES[@]} -ne 0 ]; then
      ss -4nltp | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp4-listening-exposures
      ss -4nlup | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp4-listening-exposures

      local n_tcp4=$(wc -l ${WORKING_DIRECTORY}/.tcp4-listening-exposures | awk '{print $1}')
      local n_udp4=$(wc -l ${WORKING_DIRECTORY}/.udp4-listening-exposures | awk '{print $1}')

      echo "[Info] $n_tcp4 TCP4 listening strategies have been saved in ${WORKING_DIRECTORY}/.tcp4-listening-exposures"
      echo "[Info] $n_udp4 UDP4 listening strategies have been saved in ${WORKING_DIRECTORY}/.udp4-listening-exposures"
   fi

   if [ ${#EXTERNAL_IPV6_ADDRESSES[@]} -ne 0 ]; then
      ss -6nltp | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.tcp6-listening-exposures
      ss -6nlup | awk '{print $4,$5,$6}' | tail -n +2 >> ${WORKING_DIRECTORY}/.udp6-listening-exposures

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
   local tcp4DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print $2":"$3}' ${WORKING_DIRECTORY}/.tcp4-dnat-exposures | awk -F: '{
      split($2, ports, ",")
      for (i in ports) {
         print $1 ":" ports[i]
      }
   }' | sort -u))

   # Format TCP4 Listening exposures
   local tcp4ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.tcp4-listening-exposures | sort -u))

   # Merge TCP4 exposures
   local tcp4Exposures=( ${tcp4DnatExposures[@]} ${tcp4ListeningExposures[@]} )

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

   # [2] Generate UDP4 exposures
   # Format UDP4 DNAT exposures: [1] 0.0.0.0/0;<port> → 0.0.0.0:<port> [2] 0.0.0.0:<port1>,<port2> → 0.0.0.0:<port1> and 0.0.0.0:<port2> [3] unique sort
   local udp4DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print $2":"$3}' .udp4-dnat-exposures | awk -F: '{
      split($2, ports, ",")
      for (i in ports) {
         print $1 ":" ports[i]
      }
   }' | sort -u))

   # Format UDP4 Listening exposures
   local udp4ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.udp4-listening-exposures | sort -u))

   # Merge UDP4 exposures
   local udp4Exposures=( ${udp4DnatExposures[@]} ${udp4ListeningExposures[@]} )

   # Eliminate duplicates and save to temporary file
   echo ${udp4Exposures[@]} | tr ' ' '\n' | sort -u > .udp4-exposures.tmp

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
      }' .udp4-exposures.tmp | sort -u > .udp4-exposures
   
   # Remove temporary file
   /usr/bin/rm -f ${WORKING_DIRECTORY}/.udp4-exposures.tmp

   local n_udp4=$(wc -l ${WORKING_DIRECTORY}/.udp4-exposures | awk '{print $1}')
   echo "[Info] $n_udp4 UDP4 exposures have been saved in ${WORKING_DIRECTORY}/.udp4-exposures"

   # [3] Generate TCP6 exposures
   # Format TCP6 DNAT exposures:
   # ::/0;<port> → [::]:<port>
   # [::]:<port1>,<port2>,... → [::]:<port1> [::]:<port2> ...
   # unique sort
   local tcp6DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print "["$2"]:"$3}' .tcp6-dnat-exposures | awk -F']:' '{
      split($2, ports, ",")
      for (i in ports) {
         print $1 "]:" ports[i]
      }
   }' | sort -u))

   # Format TCP4 Listening exposures
   local tcp6ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.tcp6-listening-exposures | sort -u))

   # Merge TCP4 exposures
   local tcp6Exposures=( ${tcp6DnatExposures[@]} ${tcp6ListeningExposures[@]} )

   # Eliminate duplicates and save to temporary file
   echo ${tcp6Exposures[@]} | tr ' ' '\n' | sort -u > .tcp6-exposures.tmp

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
      }' .tcp6-exposures.tmp | sort -u > .tcp6-exposures
   
   # Remove temporary file
   /usr/bin/rm -f ${WORKING_DIRECTORY}/.tcp6-exposures.tmp

   local n_tcp6=$(wc -l ${WORKING_DIRECTORY}/.tcp6-exposures | awk '{print $1}')
   echo "[Info] $n_tcp6 TCP6 exposures have been saved in ${WORKING_DIRECTORY}/.tcp6-exposures"

   # [4] Generate UDP6 exposures
   local udp6DnatExposures=($(awk -F';' '{$2 = gensub(/\/0/,"","g",$2); print "["$2"]:"$3}' .udp6-dnat-exposures | awk -F']:' '{
      split($2, ports, ",")
      for (i in ports) {
         print $1 "]:" ports[i]
      }
   }' | sort -u))

   # Format UDP6 Listening exposures
   local udp6ListeningExposures=($(awk '{print $1}' ${WORKING_DIRECTORY}/.udp6-listening-exposures | sort -u))

   # Merge UDP6 exposures
   local udp6Exposures=( ${udp6DnatExposures[@]} ${udp6ListeningExposures[@]} )

   # Eliminate duplicates and save to temporary file
   echo ${udp6Exposures[@]} | tr ' ' '\n' | sort -u > .udp6-exposures.tmp

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
      }' .udp6-exposures.tmp | sort -u > .udp6-exposures
   
   # Remove temporary file
   /usr/bin/rm -f ${WORKING_DIRECTORY}/.udp6-exposures.tmp

   local n_udp6=$(wc -l ${WORKING_DIRECTORY}/.udp6-exposures | awk '{print $1}')
   echo "[Info] $n_udp6 UDP6 exposures have been saved in ${WORKING_DIRECTORY}/.udp6-exposures"
}

#
# [Note] Preventive iptables strategies opening (预防性策略放通) is necessary to prevent ports from being inaccessible during wildcard network security reinforcement on the host. For example, adding the 0.0.0.0/0 to 0.0.0.0/0 ANY REJECT policy may cause communication failure between containers sharing the same docker container bridge on the current node. Therefore, it is necessary to open the DOCKER-BRIDGE-SUBNET TO DOCKER-BRIDGE-SUBNET ANY ALLOW strategy.
#
preventive_iptables_allow_rules() {

   local i=
   
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_service_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file
   # Don't forget the loopback subnets

   overwrite_shell_script_header ${WORKING_DIRECTORY}/.preventive-allow-script

   echo "ipset create permit-subnets-ipv4 hash:net" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ipset create permit-subnets-ipv6 hash:net" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   for i in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${SERVICE_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]} ${LOOPBACK_SUBNETS_IPV4}; do
      echo "ipset add permit-subnets-ipv4 $i" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   done

   for i in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${SERVICE_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]} ${LOOPBACK_SUBNETS_IPV6}; do
      echo "ipset add permit-subnets-ipv6 $i" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   done

   # TCP4/UDP4 OUTBOUND
   echo "iptables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv4 src -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "iptables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv4 src -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   # TCP4/UDP4 INBOUND
   echo "iptables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv4 dst -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "iptables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv4 dst -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   # TCP6/UDP6 OUTBOUND
   echo "ip6tables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv6 src -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ip6tables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv6 src -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   # TCP6/UDP6 INBOUND
   echo "ip6tables -t raw -C PREROUTING -m set --match-set permit-subnets-ipv6 dst -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.preventive-allow-script
   echo "ip6tables -t raw -I PREROUTING -m set --match-set permit-subnets-ipv6 dst -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.preventive-allow-script

   echo "[Info] The preventive iptables allow rules have been saved in ${WORKING_DIRECTORY}/.preventive-allow-script"
}

get_packets_filter_file_by_exposures () {

   # Load private client subnets of current host. It should be noted that service CIDR can only be used as the destination, not as the client. In addition, traffic capture will be performed on external network interfaces rather than [any], so the filtering conditions for the loopback network can be ignored.
   load_docker_subnet_addresses_from_file
   load_cluster_cidr_from_file
   load_kvm_subnet_addresses_from_file
   load_vmware_subnet_addresses_from_file

   # [1] TCP4 filters
   echo '[Info] TCP4 filters:'

   # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
   echo -n 'ip and tcp' | tee ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter

   # Filter out request packets from private subnets
   for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]}; do
      echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter
   done

   # Add destination address filtering criteria
   echo -n ' and ( ' | tee -a .tcp4-exposures-packets-filter
   awk -F: '{a[$1]=a[$1]?a[$1]" or dst port "$2:$2} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' .tcp4-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter
   echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter

   # [2] UDP4 filters
   echo -e '\n[Info] UDP4 filters:'

   # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
   echo -n 'ip and udp' | tee ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter

   # Filter out request packets from private subnets
   for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV4[@]} ${CLUSTER_CIDR_IPV4[@]} ${KVM_SUBNET_ADDRESSES_IPV4[@]} ${VMWARE_SUBNET_ADDRESSES_IPV4[@]}; do
      echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
   done

   # Add destination address filtering criteria
   echo -n ' and ( ' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
   awk -F: '{a[$1]=a[$1]?a[$1]" or dst port "$2:$2} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' .udp4-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter
   echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter

   # [3] TCP6 filters
   echo -e '\n[Info] TCP6 filters:'
   
   # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
   echo -n 'ip6 and tcp' | tee ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter

   # Filter out request packets from private subnets
   for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]}; do
      echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter
   done

   # Add destination address filtering criteria
   echo -n ' and ( ' | tee -a .tcp6-exposures-packets-filter
   awk -F']:' '{addr = $1; port = $2; gsub(/^\[/, "", addr); a[addr]=a[addr]?a[addr]" or dst port "port:port} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' .tcp6-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter
   echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter

   # [4] UDP6 filters
   echo -e '\n[Info] UDP6 filters:'

   # Add IP address family filtering criteria and TCP/UDP protocol type filtering criteria
   echo -n 'ip6 and udp' | tee ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter

   # Filter out request packets from private subnets
   for srcNet in ${DOCKER_NETWORK_SUBNETS_IPV6[@]} ${CLUSTER_CIDR_IPV6[@]} ${KVM_SUBNET_ADDRESSES_IPV6[@]} ${VMWARE_SUBNET_ADDRESSES_IPV6[@]}; do
      echo -n " and not src net $srcNet" | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
   done

   # Add destination address filtering criteria
   echo -n ' and ( ' | tee -a .udp6-exposures-packets-filter
   awk -F']:' '{addr = $1; port = $2; gsub(/^\[/, "", addr); a[addr]=a[addr]?a[addr]" or dst port "port:port} END{for(i in a) print "dst host "i" and ( dst port "a[i]" ) or"}' .udp6-exposures | tr '\n' ' ' | sed 's# or $##g' | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
   echo -n ' )' | tee -a ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter
}

get_packets_capture_script() {

   load_external_interfaces_from_file

   local i=
   for i in ${EXTERNAL_INTERFACES[@]}; do

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp4-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp4-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.tcp6-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts

      echo "timeout ${PACKETS_CAPTURE_DURATION} tcpdump -i $i -lqnn -F ${WORKING_DIRECTORY}/.udp6-exposures-packets-filter" | tee -a ${WORKING_DIRECTORY}/.packets-capture-scripts
   done

   echo "[Info] Packets capture scripts have saved in ${WORKING_DIRECTORY}/.packets-capture-scripts"
}

run_capture_and_summarize_connections() {

   local tcpdumpScript="${*}"
   local protoType=$(echo "$tcpdumpScript" | sed 's#.*\.\([cdtup46]*\)-exposures-packets-filter$#\1#g')
   local connectionSummaryPath=${WORKING_DIRECTORY}/.$protoType-connections-summary

   if [ -z "$tcpdumpScript" ] || [ -z "$protoType" ]; then
      echo '[Info] Please provide a valid packet capture script.'
      exit -1
   fi

   touch $connectionSummaryPath

   eval "$tcpdumpScript" 2>/dev/null | while IFS= read -r line; do
      local packet=$(echo $line | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5} > ([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5}' | sed 's/\.[0-9]* > /,/g')
      # Add parameter FX to avoid partial content matching
      if [ $(grep -Fx $packet $connectionSummaryPath | wc -l) -eq 0 ]; then
         echo $packet >> $connectionSummaryPath
      fi
   done

   echo "[Info] The packets have been summarized into file $connectionSummaryPath"
}

concurrently_run_packets_captures() {

   if [ ! -f ${WORKING_DIRECTORY}/.packets-capture-scripts ]; then
      echo "[Warn] Cannot find file ${WORKING_DIRECTORY}/.packets-capture-scripts"
      exit -1
   fi

   local IFS=$'\n'
   local tcpdumpScript=

   for tcpdumpScript in $(cat ${WORKING_DIRECTORY}/.packets-capture-scripts); do
      nohup $0 --run-capture-and-summarize-connections "$tcpdumpScript" &
   done
}

#
# [Note]
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

         echo "ipset destroy allowed_tcp4_to_$destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

         echo "ipset create allowed_tcp4_to_$destinationHost:$destinationPort hash:ip" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script

         for j in ${sourceHosts[@]}; do
            echo "ipset add allowed_tcp4_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script
         done

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

         echo "ipset destroy allowed_udp4_to_$destinationHost:$destinationPort" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         echo "ipset create allowed_udp4_to_$destinationHost:$destinationPort hash:ip" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         for j in ${sourceHosts[@]}; do
            echo "ipset add allowed_udp4_to_$destinationHost:$destinationPort $j" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script
         done

         echo "iptables -t raw -C PREROUTING -p udp -m set --match-set allowed_udp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT || \\" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         echo "iptables -t raw -I PREROUTING -p udp -m set --match-set allowed_udp4_to_$destinationHost:$destinationPort src -d $destinationHost --dport $destinationPort -m comment --comment \"Unified Access Control\" -j ACCEPT" >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

         echo >> ${WORKING_DIRECTORY}/.udp4-exposures-allow-script

      done

      echo "[Info] The TCP4 allow rules have been saved in ${WORKING_DIRECTORY}/.tcp4-exposures-allow-script"
   fi
}

#
# [Note] Generate iptables blocking strategy script based on port exposure surface file.
#
get_iptables_reject_rules_from_exposures() {

   local IFS=$'\n'
   local i=

   if [ -f ${WORKING_DIRECTORY}/.tcp4-exposures ]; then

      overwrite_shell_script_header ${WORKING_DIRECTORY}/.tcp4-exposures-reject

      # Convert the list of <HOST_IP>:<EXPOSED_PORT> to <HOST_IP> <EXPOSED_PORT_1>[,<EXPOSED_PORT_1>...] format
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

# 考虑到有些 高版本的k8s集群，由之前的显示监听变为了“端口隐式监听，用ss/netstat查不到显式的LISTEN状态，但端口能接收流量,不创建 “用户# 态监听进程”，而是通过iptables规则直接将宿主机NodePort的流量转发到 Pod（属于 “隐式监听”）
# check_nodeport_netstat() {

#     # 检查kubectl命令是否存在
#     if ! command -v kubectl &> /dev/null; then
#         echo "未检测到kubectl命令，不执行NodePort检查"
#         return  # 直接返回，不修改全局变量
#     fi

#     # 获取第一个NodePort类型Service的暴露端口
#     local NODE_PORT=$(kubectl get svc -A | grep -i nodeport | head -n 1 | awk '{print $(NF-1)}' | awk -F: '{print $2}' | awk -F/ '{print $1}')

#     # 检查是否找到NodePort端口
#     if [ -z "$NODE_PORT" ]; then
#         echo "未找到NodePort类型的Service"
#         return  # 未找到时保持全局变量默认值
#     fi

#     # 用netstat检查端口并输出对应提示
#     if netstat -tanlp 2>/dev/null | grep -q ":$NODE_PORT"; then
#         k8s_svc_nodeport_can_be_seen_netstat=true
#         echo "此k8s集群的NodePort类型的service 可以通过netstat 命令检查到"
#     else
#         k8s_svc_nodeport_can_be_seen_netstat=false
# 	# k8s NodePort类型的service 端口不能被netstat检查到，要调用下面的方法汇聚所有ns暴露的端口，填充到全局变量all_ns_port数组
# 	find_all_ns_exposed_host_ports_with_mapping
#         echo "此k8s集群的NodePort类型的service 端口不能被netstat命令检查不到，通过iptables的nat表的流量转发到后端的pod!"
#     fi

#     perl -p -i -e "s#^k8s_svc_nodeport_can_be_seen_netstat=.*#k8s_svc_nodeport_can_be_seen_netstat=${k8s_svc_nodeport_can_be_seen_netstat}#g" $0
# }

#
# 5. Start host captures for all listening addresses
#
# run_host_caps() {

#    # The assembled filter
#    local filter=

#    # Perform a inspection of all addresses of all interfaces. Loopback network is not controlled by iptables and will be no longer considered!
#    local arrIpLocal=(`get_host_ip_arr`)

#    # Assember the dst host filter
#    filter='('
#    local isFirst=true
#    for ipLocal in ${arrIpLocal[@]}; do
#       if $isFirst; then
#          isFirst=false
#       else
#          filter=$filter' or'
#       fi
#       filter=$filter' dst host '$ipLocal
#    done
#    filter=$filter' )'


   
# # 判断变量值
# if [ "${Block_only_panji}" = false ]; then
# 	echo "----------------- Block_only_panji: ${Block_only_panji}">>tcpdump.log
#    # Obtaining possible listening addresses, such as listening at 0.0.0.0 and :::, means receiving incoming connections from any local network interface, and also includes the IP address bound by a valid network adapters.
#    local effLsnIps=`echo ${arrIpLocal[@]} | sed 's/ /|/g'`'|0.0.0.0|:::'

#    # Perform a inspection of all outside listening ports of this host.
#    local lsnPorts=(`netstat -an | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $NF == "LISTEN" {print $4}' | sed 's/.*:\([0-9]*\)$/\1/g' | sort -u -n`)

#    # If the current node is configured with a port forwarding strategy outside of the explicit listening port, it still needs to be blocked!
#    local fwdPorts=(`iptables -t nat -L PREROUTING -n | awk '$1 == "DNAT" {print $0}' | sed 's/.*dpt:\([0-9]*\)\ .*/\1/g' | sort -u -n`)
#    # 考虑第二种目标类型 ：REDIRECT
#    local fwdPorts2=(`iptables -t nat -L PREROUTING -n| awk '$1 == "REDIRECT" {print $0}'| sed -n -E 's/.*dpt:([0-9]+).*/\1/p'| sort -u -n`)

# # 调用检查k8s集群 类型为NodePort类型的svc 暴露的端口能否被netstat检查到的函数,如果检查不到，把全局变量k8s_svc_nodeport_can_be_see
# # n_netstat赋值为false,并在这个函数里面调用find_all_ns_exposed_host_ports_with_mapping()，搜集k8s 集群内所有名称空间暴露的端口装配成# 数组赋值给全局变量all_ns_port
#    check_nodeport_netstat
#  # 如果是k8s svc nodePort类型，用netstat 检查不到，
#    if [ "$k8s_svc_nodeport_can_be_seen_netstat" = false ]; then
#       # Merge listening ports and forwarding ports and redirect ports
#       local mergedPorts=( ${lsnPorts[@]} ${fwdPorts[@]} ${fwdPorts2[@]} ${all_ns_port[@]} )
#       mergedPorts=($(printf "%s\n" "${mergedPorts[@]}" | sort -u))
#       echo "--------mergedPorts:   ${mergedPorts[@]}">>tcpdump.log
#    else
#      # k8s svc nodePort类型，用netstat 检查 Merge listening ports and forwarding ports and redirect ports
#      local mergedPorts=( ${lsnPorts[@]} ${fwdPorts[@]} ${fwdPorts2[@]} )
#      echo "--------mergedPorts:   ${mergedPorts[@]}">>tcpdump.log
#    fi

#    # Resort the ports
#    local allPorts=(`echo ${mergedPorts[@]} | sed 's/ /\n/g' | sort -u -n`)

#    # Convert ports list to port ranges list
#    local allPortRanges=(`ports_range "${allPorts[@]}"`)
#    # Assemble the listening port ranges filter
#    local rangeFilter=$(echo ${allPortRanges[@]} | sed 's/ /\n/g' | sed 's/^/or dst portrange /g' | tr '\n' ' ' | sed 's/^or//')
# else
#    local allPorts=(`echo ${pj_port[@]} | sed 's/ /\n/g' | sort -u -n`)
#    # Convert panji ports list to port ranges list
#    local pj_allPortRanges=(`ports_range "${allPorts[@]}"`)
#    # Assemble the listening port ranges filter
#    local rangeFilter=$(echo ${pj_allPortRanges[@]} | sed 's/ /\n/g' | sed 's/^/or dst portrange /g' | tr '\n' ' ' | sed 's/^or//')
    
# fi
#    rangeFilter="($rangeFilter)"

#    # Reset the quintet file
#    >quintet.txt

#    # Added irrelevant feature: Obtain the mapping relationship between ports and processes
#    netstat -anp | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $6 == "LISTEN" {print $4","$7}' | sed 's/.*:\([0-9]*,.*\)/\1/g' | sort -t, -u -k1n > map-ports-procs.txt

#    # Begin to capture
#    nohup $0 --run-caps --filter "$filter and $rangeFilter" &

#    echo "[Info] Started $nProc tcpdump packet capture processes!"
# }

# #
# # 6. Perform a single capture with one filter
# #
# run_cap() {

#    if [ -z "$1" ]; then
#       echo '[Warn] Pls provide the capture filter, such as dst port 80.'
#       return
#    fi

#    # [Note] The traffic between K8s nodes, K8s pods and standalone containers has been fully released, should be excluded here.

#    get_curr_node_ip

#    # 1. Obtain the K8s nodes filter
#    local nodesFilter=

#    # Obtain all IPs of all interfaces
#    local ipArr=(`ip a | grep inet | grep -E -o '([0-9a-fA-F:]+)/[0-9]{1,3}|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -F'/' '{print $1}' | grep -vE '127.0.0.1|::1' | sort | uniq`)
#    if [ ${#ipArr[@]} -eq 0 ]; then
#       echo '[Warn] Cannot obtain the IPs of all interfaces!'
#       exit 1
#    fi

#    # Solving the intersection of K8s cluster node IP and current node interface IP
#    local intersect=(`echo ${nodes[*]} ${ipArr[*]} | sed 's/ /\n/g' | sort | uniq -c | awk '$1!=1{print $2}'`)


  

#    # Compress the node list into a subnet list
#    echo "nodes: ====================== ${nodes[@]}">>tcpdump.log
#    # eg:192.168.80.11-15，192.168.80.11/32 , 192.168.80.12/30(192.168.80.12-15)包含主机2为全为0的网络号和主机位全1的广播IP
#    local arrSubnets=(`python2 iprange.py --to-subnets ${nodes[@]}`)
#    echo "arrSubnets: ---------------------------${arrSubnets[@]}" >>tcpdump.log
#    if [ ${#arrSubnets[@]} -ne 0 ]; then
#       nodesFilter=$(echo ${arrSubnets[@]} | sed 's/ /\n/g' | sed 's/^/and not src net /g' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
#    fi
#    echo "[Info] The filter of cluster nodes: $nodesFilter." >> tcpdump.log

#    # 2. Obtain the K8s pod CIDR filter
#    local podCidrFilter=
#    # Call the get_pod_cidr() function to initialize the value of the global variable podCidr
#    get_pod_cidr
#    if [ ! -z $podCidr ]; then
#       podCidrFilter="and not src net $podCidr"
#    fi
#    echo "[Info] The filter of K8s pods CIDR: $podCidrFilter."

#    # 3. Obtain the container subnet filter
#    local cntrFilter=
#    local arrSubCntr=($(docker network inspect `docker network ls --format '{{.Name}}'` 2>/dev/null | jq -r -c '.[].IPAM.Config|.[].Subnet'))
#    if [ ${#arrSubCntr[@]} -ne 0 ]; then
#       cntrFilter=$(echo ${arrSubCntr[@]} | sed 's/ /\n/g' | sed 's/^/and not src net /g' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
#    fi
#    echo "[Info] The filter of container network bridges: $cntrFilter."

#    # [Note] The following is an explanation of the enabled parameters:
#    # -l: Make stdout line buffered.  Useful if you want to see the data while capturing it.
#    # -nn: Don't convert protocol and port numbers etc. to names either.
#    # -q: Print less protocol information so output lines are shorter.
#    local s="timeout $duration tcpdump -i any -lqnn '$1 $nodesFilter $podCidrFilter $cntrFilter'"
#    echo "nodesFilter: "$nodesFilter >>tcpdump.log
#    echo "podCidrFilter= "$podCidrFilter >>tcpdump.log
#    echo "cntrFilter= "$cntrFilter >>tcpdump.log
#    echo $s >>tcpdump.log

#    echo "[Info] The traffic capturing statement: $s."
#    eval $s 2>/dev/null | while IFS= read -r line; do
#       local plc=`echo $line | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5} > ([0-9]{1,3}\.){3}[0-9]{1,3}\.[0-9]{1,5}' | sed 's/\.[0-9]* > /,/g'`
#       # 增加参数-Fx避免部分内容匹配，如192.168.80.100,192.168.80.11.22365，没有192.168.80.100,192.168.80.11.22 也可以匹配上的问题
#       if [ `grep -Fx $plc quintet.txt | wc -l` -eq 0 ]; then
#          echo $plc >> quintet.txt
#       fi
#    done
# }

# #
# # 7. Comprehensive release of strategies between K8s nodes. Prerequisite: The node list configured in the current script is correct.
# #
# add_k8s_nodes_plcs() {

#    if [ ${#nodes[@]} -eq 0 ]; then
#       echo '[Warn] The nodes list is empty, pls use get_nodes() method to update the list first!'
#       get_nodes
#    fi

#    get_curr_node_ip

#    if [ -z "$currNodeIP" ]; then
#       echo '[Warn] The data in the node list may not be accurate!'
#       return
#    fi

#    echo '[Info] Adding K8s nodes policies ...'

#    echo | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo '# Policies for K8s Nodes         #' | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo | tee -a block.sh


#    # Convert node list to ip range list
#    local arrIpRange=(`python2 iprange.py --to-ranges ${nodes[@]}`)

#    # Add ip range list to accept policies
#    for ipRange in ${arrIpRange[@]}; do
#       echo "iptables -t raw -I PREROUTING -p tcp -m iprange --src-range $ipRange -j ACCEPT" | tee -a block.sh
#    done

#    echo '[Info] Done.'
# }

# #
# # 8. Add an exception policies for K8s pods accessing open services on the current host.
# #
# add_k8s_pods_plcs() {

#    if [ -z $podCidr ]; then
#       return
#    fi

#    echo '[Info] Adding K8s pods policies ...'

#    echo | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo '# Policies for K8s pods          #' | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo | tee -a block.sh

#    echo "iptables -t raw -I PREROUTING -p tcp -s $podCidr -j ACCEPT # K8s pods policies" | tee -a block.sh

#    echo '[Info] Done.'
# }

# #
# # 9. Add an exception policies for standalone containers accessing open services on the current host.
# #
# add_cntr_plcs() {

#    # Obtain the subnet list of all container network bridges
#    local arrSubCntr=($(docker network inspect `docker network ls --format '{{.Name}}'` 2>/dev/null | jq -r -c '.[].IPAM.Config|.[].Subnet'))

#    # Check if relevant strategies are involved
#    if [ ${#arrSubCntr[@]} -eq 0 ]; then
#       return
#    fi

#    echo '[Info] Adding container policies ...'

#    echo | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo '# Policies for docker containers #' | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo | tee -a block.sh

#    for subCntr in ${arrSubCntr[@]}; do
#       echo "iptables -t raw -I PREROUTING -p tcp -s $subCntr -j ACCEPT # Standalone docker policies" | tee -a block.sh
#    done

#    echo '[Info] Done.'
# }

# #
# # 10. Generate block scripts such as:
# # iptables -t raw -A PREROUTING -p tcp -s 134.80.15.198 --dport 2181 -j ACCEPT
# # iptables -t raw -A PREROUTING -p tcp -m tcp --dport 2181 -j DROP
# #
# gen_block_scripts() {

#    # 因为生成的封堵脚本会用到变量all_ns_port，因此需要调用这个函数,这个函数里面调用find_all_ns_exposed_host_ports_with_mapping，搜集k8s 集群内所有名称空间暴露的端口装配成数组赋值给全局变量all_ns_port
#    check_nodeport_netstat

	
#    if [ ! -f quintet.txt ]; then
#       echo '[Warn] The IP quintuple file has not yet been created!'
#       return
#    fi

#    echo '[Info] Generating network blocking script ...'

#    echo '#####################################' | tee block.sh
#    echo '# IPTABLES Blocking Scripts v240317 #' | tee -a block.sh
#    echo '#####################################' | tee -a block.sh

#    echo | tee -a block.sh
#    echo '#!/bin/bash' | tee -a block.sh

#    echo | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo '# Policies for Local Loopback Address #' | tee -a block.sh
#    echo '##################################' | tee -a block.sh
#    echo | tee -a block.sh
#    echo "iptables -t raw -I PREROUTING -p tcp -s 127.0.0.0/8 -j ACCEPT # local loopback address policies"|tee -a block.sh
   
#    add_k8s_nodes_plcs

#    add_k8s_pods_plcs

#    add_cntr_plcs

#    # General Blocking Scripts
#    echo | tee -a block.sh
#    echo '############################' | tee -a block.sh
#    echo '# General Blocking Scripts #' | tee -a block.sh
#    echo '############################' | tee -a block.sh

#    echo | tee -a block.sh
#    sort -t. -k8n quintet.txt | grep -v '^$' | while IFS= read -r line; do
#       local srcAddr=`echo $line | awk -F',' '{print $1}'`
#       local dstPort=`echo $line | awk -F',' '{print $2}' | awk -F'.' '{print $NF}'`
#       local procName=`grep "^$dstPort," map-ports-procs.txt | head -1 | awk -F, '{print $2}'`
#       echo "iptables -t raw -A PREROUTING -p tcp -s $srcAddr --dport $dstPort -j ACCEPT # "$procName | tee -a block.sh
#    done

#    # Perform a inspection of all addresses of all interfaces. Loopback network is not controlled by iptables and will be no longer considered!
#    local arrIpLocal=(`get_host_ip_arr`)

#    # Obtaining possible listening addresses, such as listening at 0.0.0.0 and :::, means receiving incoming connections from any local network interface, and also includes the IP address bound by a valid network adapters.
#    local effLsnIps=`echo ${arrIpLocal[@]} | sed 's/ /|/g'`'|0.0.0.0|:::'

#    # Perform a inspection of all outside listening ports of this host.
#    local lsnPorts=(`netstat -an | awk '$1 ~ "tcp" && $4 ~ "'$effLsnIps'" && $NF == "LISTEN" {print $4}' | sed 's/.*:\([0-9]*\)$/\1/g' | sort -u -n`)
# if [ "$k8s_svc_nodeport_can_be_seen_netstat" = false ]; then
# echo "before=================== lsnPorts: ${lsnPorts[@]}">>tcpdump.log
# echo "before=================== all_ns_port: ${all_ns_port[@]}">>tcpdump.log
#  lsnPorts=("${lsnPorts[@]}" "${all_ns_port[@]}")  
#  echo "wo@@@@@@=====lsnPorts: ${lsnPorts[@]}">>tcpdump.log
#  lsnPorts=($(printf "%s\n" "${lsnPorts[@]}" | sort -u -n))
# echo "after=================== lsnPorts: ${lsnPorts[@]}">>tcpdump.log
# echo "after=================== all_ns_port: ${all_ns_port[@]}">>tcpdump.log
# fi

#    local lsnPortsRanges=(`ports_range "${lsnPorts[@]}"`)
#    # Adding multiple ports blocking policy
#    local sLsnPorts=`echo ${lsnPortsRanges[@]} | sed 's/ /,/g'`
#    # -A PREROUTING -p tcp -m multiport --dports 3312,4443,50101,51012,51021,61588,6443,80,8001,8008,8443,9091,9093 -j DROP
#    # Fix the issue where the multiport module in iptables supports a maximum of 15 ports.
#    # This  module  matches  a  set of source or destination ports.  Up to 15 ports can be specified.  A port range (port:port)
#    # counts as two ports.
# # 如果执行该脚本传入了--block-only-panji,就只封堵panji名称空间暴露的port
# if [ "${Block_only_panji}" = "true" ]; then
# 	echo "Block_only_panji : ${Block_only_panji}}" >>tcpdump.log
#    local sLsnPorts=`echo ${pj_port[@]} | sed 's/ /,/g'`
#    echo "=== block only panj,sLsnPorts is ${sLsnPorts[@]}">>tcpdump.log
# fi
#    IFS=',' read -ra P <<< "$sLsnPorts"
#    count=0
#    chunk=""
#    for p in "${P[@]}"; do
#     p=${p//-/:}   # 替换成冒号范围

#     # 如果已经14个了，且当前是port范围 -> 先输出当前规则，范围放到下一条
#     if ((count == 14)) && [[ $p == *:* ]]; then
#         echo "iptables -t raw -A PREROUTING -p tcp -m multiport --dports $chunk -j DROP" | tee -a block.sh
#         count=0
#         chunk=""
#     fi

#     # 加入本次元素
#     [[ -n $chunk ]] && chunk+=","
#     chunk+="$p"

#     if [[ $p == *:* ]]; then
#         ((count+=2))
#     else
#         ((count+=1))
#     fi

#     if ((count >= 15)); then
#         echo "iptables -t raw -A PREROUTING -p tcp -m multiport --dports $chunk -j DROP" | tee -a block.sh
#         count=0
#         chunk=""
#     fi
#    done
#    # 输出剩余 chunk
#    if [[ -n $chunk ]]; then
#     echo "iptables -t raw -A PREROUTING -p tcp -m multiport --dports $chunk -j DROP" | tee -a block.sh
#    fi
# }

# #
# # 11. Revoke all iptables blocking policies that have already been added
# #
# disable_block() {
   
#    # Step1. Unlock all drop restrictions
#    iptables -t raw -L PREROUTING --line-numbers --numeric | awk '$2 == "DROP" {print $1}' | sort -nr | while IFS= read -r line; do
#       iptables -t raw -D PREROUTING $line
#    done

#    # Step2. Remove all accept policies
#    iptables -t raw -L PREROUTING --line-numbers --numeric | awk '$2 == "ACCEPT" {print $1}' | sort -nr | while IFS= read -r line; do
#       iptables -t raw -D PREROUTING $line
#    done
# }

# #
# # 12. Iptables persistence: After the next restart, the saved iptables policy will automatically take effect!
# #
# reserve_iptables() {

#    if [ -z `rpm -qa iptables-services` ]; then
#       echo '[Warn] You must install iptables-services first: yum -y install iptables-services!'
#       return
#    fi

#    service iptables save

#    if [ ! -f /etc/sysconfig/iptables ]; then
#       echo '[Warn] Iptables not successfully backed up to /etc/sysconfig/iptables!'
#       return
#    fi

#    systemctl enable iptables --now
# }

# #
# # 13. Add exception policy, take effect immediately
# #
# add_except() {

#    local srcHost=$1
#    local dstPort=$2

#    if [ -z $srcHost ] || [ -z $dstPort ]; then
#       echo '[Warn] You at least provide source IP address and destination port number!'
#       return
#    fi

#    local procName=`grep "^$dstPort," map-ports-procs.txt | head -1 | awk -F, '{print $2}'`

#    # Add exception policy to block.sh
#    local plc="iptables -t raw -I PREROUTING -p tcp -s $srcHost --dport $dstPort -j ACCEPT # $procName"
#    echo $plc >> block.sh
   
#    eval "$plc"
# }

# #
# # 14. Load exception policies from configuration file
# #
# add_cfg_excepts() {
#    echo 'Not implemented'
# }

# #
# # 15. Review the traffic after blocking, observe the blocking effect, and manually review whether some traffic should be released.
# #
# traff_review() {

   
#    get_curr_node_ip
# }

# #
# # Dispatch capturing jobs for general nodes
# #
# # dispatch_caps() {
# #    echo 'Not Implemented Feature'
# # }

# #
# # Dispatch capturing jobs for all K8s nodes
# #
# dispatch_caps() {

#    # Refresh nodes list
#    get_nodes

#    # Convert array to csv
#    local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

#    # Obtain the pods CIDR
#    get_pod_cidr

#    # Obtain the file name of current shell
#    local selfName=$(basename $0)

#    # Obtain the file name of current shell without extension name
#    local noExt=$(echo $selfName | sed 's/^\(.*\)\.[0-9A-Za-z]*$/\1/g')

#    # Assemble the log file name
#    local logFileName=$noExt'.log'

#    # Work Folder

#    ansible all -i "$nodesList" -m shell -a "mkdir -p ${WORKING_DIRECTORY}" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=$0 dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=ipaddress-1.0.23-py2.py3-none-any.whl dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=iprange.py dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "cd ${WORKING_DIRECTORY}; chmod +x $selfName; nohup ./$selfName --run-host-caps 1>>$logFileName 2>>$logFileName &" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "echo -n 'Capturing processes num: '; ps -ef | grep tcpdump | grep -vE 'grep|timeout' | wc -l" -f ${#nodes[@]} -o
# }

# qry_cap_proc_num() {

#    # Refresh nodes list
#    get_nodes

#    # Convert array to csv
#    local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

#    ansible all -i "$nodesList" -m shell -a "echo -n 'Capturing processes num: '; ps -ef | grep tcpdump | grep -vE 'grep|timeout' | wc -l" -f ${#nodes[@]} -o
# }

# #
# # Dispatch tasks of blocking scripts generation
# #
# dispatch_gen_tasks() {

#    # Refresh nodes list
#    get_nodes

#    # Convert array to csv
#    local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

#    # Obtain the pods CIDR
#    get_pod_cidr

#    # Obtain the file name of current shell
#    local selfName=$(basename $0)

#    ansible all -i "$nodesList" -m shell -a "mkdir -p ${WORKING_DIRECTORY}" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=$0 dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "cd ${WORKING_DIRECTORY}; chmod +x $selfName; ./$selfName --gen-block-scripts" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "cd ${WORKING_DIRECTORY}; ls -ltr block.sh" -f ${#nodes[@]} -o
# }

# #
# # Dispatch iptables block jobs
# #
# dispatch_blocks() {

#    # Refresh nodes list
#    get_nodes

#    # Convert array to csv
#    local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

#    # Obtain the pods CIDR
#    get_pod_cidr

#    # Obtain the file name of current shell
#    local selfName=$(basename $0)

#    ansible all -i "$nodesList" -m shell -a "mkdir -p ${WORKING_DIRECTORY}" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=$0 dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "cd ${WORKING_DIRECTORY}; sh block.sh" -f ${#nodes[@]}
# }

# #
# # Batchly rollback block operations.
# #
# dispatch_rollbacks() {
#    # Refresh nodes list
#    get_nodes

#    # Convert array to csv
#    local nodesList=$(echo "${nodes[@]}" | sed 's# #,#g')

#    # Obtain the pods CIDR
#    get_pod_cidr

#    # Obtain the file name of current shell
#    local selfName=$(basename $0)

#    ansible all -i "$nodesList" -m shell -a "mkdir -p ${WORKING_DIRECTORY}" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m copy -a "src=$0 dest=${WORKING_DIRECTORY}/" -f ${#nodes[@]}

#    ansible all -i "$nodesList" -m shell -a "cd ${WORKING_DIRECTORY}; chmod +x $selfName; ./$selfName --disable-block" -f ${#nodes[@]}
# }

# #########################################
# # Mappings between params and methods   #
# #########################################

# if [[ "${*}" =~ "--duration" ]]; then

#    n=`echo ${*} | sed 's/ /\n/g' | grep -A 1 "\-\-duration" | tail -1`
#    if [[ ! "$n" =~ ^[0-9]+$ ]]; then
#       echo '[Warn] Pls input a valid number!'
#       exit 1
#    fi

#    duration=$n

#    perl -p -i -e "s/^duration=.*/duration=$duration/g" $0
# fi


# # 在抓包./iptables-block.sh --run-host-caps 和生成封堵脚本./iptables-block.sh --gen-block-scripts 都需要全局变量all_ns_port，因此需要把这个函数放到这个比较靠前的位置
# #check_nodeport_netstat

# if [[ "${*}" =~ "--get-nodes" ]]; then
#    get_nodes
#    echo "[Info] The nodes are as the following:"
#    echo ${nodes[@]} | sed 's/ /\n/g' | sed 's/^/   /g'
#    exit 0
# fi

# if [[ "${*}" =~ "--get-curr-node-ip" ]]; then
#    get_curr_node_ip
#    echo "[Info] The IP of current node: $currNodeIP."
#    exit 0
# fi

# if [[ "${*}" =~ "--get-host-ip-arr" ]]; then
#    arrIpLocal=(`get_host_ip_arr`)
#    echo "[Info] The local IPs are as the following:"
#    echo ${arrIpLocal[@]} | sed 's/ /\n/g' | sed 's/^/   /g'
#    exit 0
# fi

# if [[ "${*}" =~ "--get-pod-cidr" ]]; then
#    get_pod_cidr
#    echo $podCidr
#    exit 0
# fi

# if [[ "${*}" =~ "--block-only-panji" ]]; then
#    Block_only_panji=true
#    # 主逻辑：判断是否为master节点（存在kubectl）
#    if command -v kubectl &> /dev/null; then
#        echo "检测到kubectl命令，判断为master节点，开始计算暴露端口..."
#        find_exposed_host_ports_with_mapping
#        echo "端口计算完成，已更新全局变量pj_port"
#    else
#        echo "未检测到kubectl命令，判断为普通node节点，复用全局变量pj_port现有值"
#        # 若需要在node节点设置默认值，可在此处添加，例如：
#        # pj_port=(80 443 30000)  # 示例默认端口
#    fi
   
#    # 输出全局变量状态
#    echo "====================================="
#    echo "当前全局变量pj_port的值: ${pj_port[@]}"
#    if [ -f "$pj_output_file" ]; then
#        echo "端口映射关系文件: $pj_output_file"
#    fi
#    echo "====================================="
   
# fi

# if [[ "${*}" =~ "--run-caps" ]] && [[ "${*}" =~ "--filter" ]]; then
#    filter=`echo "${*}" | awk '{for(i=3; i<=NF; i++) {printf " %s", $i}}'`
#    run_cap "$filter"
#    exit 0
# fi

# if [[ "${*}" =~ "--add-k8s-nodes-plcs" ]]; then
#    add_k8s_nodes_plcs
#    exit 0
# fi

# if [[ "${*}" =~ "--add-k8s-pods-plcs" ]]; then
#    add_k8s_pods_plcs
#    exit 0
# fi

# if [[ "${*}" =~ "--add-cntr-plcs" ]]; then
#    add_cntr_plcs
#    exit 0
# fi

# if [[ "${*}" =~ "--reserve-iptables" ]]; then
#    reserve_iptables
#    exit 0
# fi

# if [[ "${*}" =~ "--add-except" ]]; then
#    add_except
#    exit 0
# fi

# if [[ "${*}" =~ "--add-cfg-excepts" ]]; then
#    add_cfg_excepts
#    exit 0
# fi

# #
# # Manual maintenance
# #
# # for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
# #    echo $node
# #    timeout 3 scp -rp iptables-block.sh $node:/root/
# #    timeout 3 ssh $node "nohup ./iptables-block.sh --run-host-caps 1>/dev/null 2>/dev/null &"
# # done

# # for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
# #    echo $node
# #    timeout 2 ssh $node "ps -ef | grep tcpdump | grep -v grep | wc -l"
# # done

# # for node in `timeout 8 kubectl get node -o json 2>/dev/null | jq -r -c '.items[].status.addresses[]|select(.type=="InternalIP")|.address'`; do
# #    echo $node
# #    timeout 2 ssh $node "which tcpdump"
# # done

# # 1121  <------ 134.80.209.11
# # 22 4A
# # 限制目的IP

orderedPara=(
   "--dump-dnat-strategy-tables"
   "--concurrent-process-dnat-exposures"
   "--dump-listening-tables"
   "--sequential-process-listening-exposures"
   "--concurrent-process-listening-exposures"
   "--merge-exposures"
   "--get-packets-filter-file-by-exposures"
   "--get-packets-capture-script"
   "--run-capture-and-summarize-connections"
   "--concurrently-run-packets-captures"
   "--preventive-iptables-allow-rules"
   "--usage"
   "--help"
   "--manual"
)

#
# Maps between shell options and functions
#
declare -A mapParaFunc=(
   # ["--run-host-caps"]="run_host_caps"
   # ["--gen-block-scripts"]="gen_block_scripts"
   # ["--disable-block"]="disable_block"
   # ["--dispatch-caps"]="dispatch_caps"
   # ["--qry-cap-proc-num"]="qry_cap_proc_num"
   # ["--dispatch-gen-tasks"]="dispatch_gen_tasks"
   # ["--dispatch-blocks"]="dispatch_blocks"
   # ["--dispatch-rollbacks"]="dispatch_rollbacks"
   ["--dump-dnat-strategy-tables"]="dump_dnat_strategy_tables"
   ["--concurrent-process-dnat-exposures"]="concurrent_process_dnat_exposures"
   ["--dump-listening-tables"]="dump_listening_tables"
   ["--sequential-process-listening-exposures"]="sequential_process_listening_exposures"
   ["--concurrent-process-listening-exposures"]="concurrent_process_listening_exposures"
   ["--merge-exposures"]="merge_exposures"
   ["--get-packets-filter-file-by-exposures"]="get_packets_filter_file_by_exposures"
   ["--get-packets-capture-script"]="get_packets_capture_script"
   ["--run-capture-and-summarize-connections"]="run_capture_and_summarize_connections"
   ["--concurrently-run-packets-captures"]="concurrently_run_packets_captures"
   ["--preventive-iptables-allow-rules"]="preventive_iptables_allow_rules"
   ["--usage"]="usage"
   ["--help"]="usage"
   ["--manual"]="usage"
)

#
# Maps between shell options and specifications
#
declare -A mapParaSpec=(
   # ["--run-host-caps"]="Start traffic capture and analysis on the current node."
   # ["--gen-block-scripts"]="Generate block scripts to block.sh."
   # ["--disable-block"]="Unlock all restrictions, rollback the blocking operations."
   # ["--dispatch-caps"]="Dispatch capturing jobs for all K8s nodes."
   # ["--qry-cap-proc-num"]="Query the capturing processes number."
   # ["--dispatch-gen-tasks"]="Dispatch tasks of blocking scripts generation."
   # ["--dispatch-blocks"]="Dispatch iptables block jobs."
   # ["--dispatch-rollbacks"]="Batchly rollback block operations."
   ["--dump-dnat-strategy-tables"]="Query iptables DNAT strategies and save them in hidden files."
   ["--concurrent-process-dnat-exposures"]="Concurrently process iptables DNAT strategites and save them in original hidden files."
   ["--dump-listening-tables"]="Retrieve the port listening list and export it to hidden files. These hidden files are distinguished by IP address family and TCP/UDP protocols."
   ["--sequential-process-listening-exposures"]="Process the port listening list sequentially in a separate process, filtering out non exposed listening surfaces."
   ["--concurrent-process-listening-exposures"]="Multi process concurrent processing port listening list, filtering out non exposed surface listening."
   ["--merge-exposures"]="merge_exposures"
   ["--get-packets-filter-file-by-exposures"]="Generate packet capture filter files based on address family and protocol type."
   ["--get-packets-capture-script"]="Generate packet capture scripts and save them in a hidden file."
   ["--run-capture-and-summarize-connections"]="Independently execute a packet capture script and organize the data packet into a connection summary file."
   ["--concurrently-run-packets-captures"]="Read packet capture commands from the packet capture script file and execute each command in the background."
   ["--preventive-iptables-allow-rules"]="Advance policy deployment of the private network of the current node to avoid connection failure after subsequent security reinforcement."
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