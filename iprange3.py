import sys
import ipaddress
from functools import reduce

def is_ipv4(address):
    """检查是否为IPv4地址"""
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_ipv6(address):
    """检查是否为IPv6地址"""
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

def normalize_ip(ip_str):
    """标准化IP地址表示"""
    if is_ipv4(ip_str):
        return ipaddress.IPv4Address(ip_str)
    elif is_ipv6(ip_str):
        return ipaddress.IPv6Address(ip_str)
    else:
        raise ValueError(f"无效的IP地址: {ip_str}")

def merge_ip_list(ip_list):
    """合并连续的IP地址范围，支持IPv4和IPv6"""
    if not ip_list:
        return []
    
    try:
        # 标准化IP地址并排序
        normalized_ips = []
        for ip in ip_list:
            normalized_ips.append(normalize_ip(ip))
        
        # 分别处理IPv4和IPv6
        ipv4_ips = [ip for ip in normalized_ips if ip.version == 4]
        ipv6_ips = [ip for ip in normalized_ips if ip.version == 6]
        
        ipv4_ips.sort()
        ipv6_ips.sort()
        
        result = []
        
        # 合并IPv4范围
        if ipv4_ips:
            start = ipv4_ips[0]
            prev = start
            for i in range(1, len(ipv4_ips)):
                current = ipv4_ips[i]
                # 检查是否连续（IPv4）
                if current != prev + 1:
                    result.append((str(start), str(prev)))
                    start = current
                prev = current
            result.append((str(start), str(prev)))
        
        # 合并IPv6范围
        if ipv6_ips:
            start = ipv6_ips[0]
            prev = start
            for i in range(1, len(ipv6_ips)):
                current = ipv6_ips[i]
                # 检查是否连续（IPv6）
                if current != prev + 1:
                    result.append((str(start), str(prev)))
                    start = current
                prev = current
            result.append((str(start), str(prev)))
        
        return result
    
    except Exception as e:
        raise ValueError(f"IP地址处理错误: {e}")

def convert_to_ranges(range_list):
    """将范围列表转换为可读的字符串格式"""
    s = ''
    for range_item in range_list:
        if range_item[0] == range_item[1]:
            s = s + ' ' + range_item[0]
        else:
            s = s + ' ' + range_item[0] + '-' + range_item[1]
    return s.lstrip()

def convert_to_subnets(range_list):
    """将IP范围转换为CIDR子网，支持IPv4和IPv6"""
    subnets = []
    for ip_range in range_list:
        try:
            start_ip = normalize_ip(ip_range[0])
            end_ip = normalize_ip(ip_range[1])
            
            # 使用ipaddress库的summarize_address_range函数
            summarized = ipaddress.summarize_address_range(start_ip, end_ip)
            for subnet in summarized:
                subnets.append(str(subnet))
                
        except Exception as e:
            print(f"Error processing range {ip_range}: {e}")
    
    return subnets

def print_usage(script_name):
    """打印使用说明"""
    print('[Usage] python3 ' + script_name + ' --to-ranges 192.168.0.1 192.168.0.2 192.168.0.3')
    print('[Usage] python3 ' + script_name + ' --to-subnets 192.168.0.1 192.168.0.2 192.168.0.3')
    print('[Usage] python3 ' + script_name + ' --to-ranges 2001:db8::1 2001:db8::2 2001:db8::3')
    print('[Usage] python3 ' + script_name + ' --to-subnets 2001:db8::1 2001:db8::2 2001:db8::3')
    print('\n支持混合IPv4和IPv6地址:')
    print('[Usage] python3 ' + script_name + ' --to-ranges 192.168.0.1 192.168.0.2 2001:db8::1 2001:db8::2')

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        sys.exit(-1)
    
    args = sys.argv[2:]
    
    # 验证所有IP地址的有效性
    valid_ips = []
    invalid_ips = []
    
    for ip in args:
        if is_ipv4(ip) or is_ipv6(ip):
            valid_ips.append(ip)
        else:
            invalid_ips.append(ip)
    
    if invalid_ips:
        print(f"警告: 以下IP地址无效并被忽略: {', '.join(invalid_ips)}")
    
    if not valid_ips:
        print("错误: 没有提供有效的IP地址")
        sys.exit(-1)
    
    try:
        if sys.argv[1] == '--to-ranges':
            result = merge_ip_list(valid_ips)
            print(convert_to_ranges(result))
            
        elif sys.argv[1] == '--to-subnets':
            ranges = merge_ip_list(valid_ips)
            subnets = convert_to_subnets(ranges)
            print(' '.join(subnets))
            
        else:
            print("错误: 未知的操作模式")
            print("可用模式: --to-ranges, --to-subnets")
            sys.exit(-1)
            
    except Exception as e:
        print(f"处理错误: {e}")
        sys.exit(-1)
