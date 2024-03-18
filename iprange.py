import sys
import ipaddress

def int2dot(intip):
    return '.'.join([ str( (intip>>x*8) & 0xFF ) for x in [3,2,1,0]])

def dot2int(dotip):
    return reduce( lambda r,x: int(x)+(r<<8), dotip.split('.'), 0 )

def merge_ip_list(ip_list):
    if not ip_list:
        return []
    orig = map(dot2int,ip_list)
    orig.sort()
    start = orig[0]
    prev = start-1
    res = []
    for x in orig:
        if x != prev+1:
            res.append((int2dot(start),int2dot(prev)))
            start = x
        prev = x
    res.append((int2dot(start),int2dot(prev)))
    return res

def convert(range_list):
    s = ''
    for i in range(len(range_list)):
        if range_list[i][0] == range_list[i][1]:
            s = s + ' ' + range_list[i][0]
        else:
            s = s + ' ' + range_list[i][0] + '-' + range_list[i][1]
    return s

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('[Usage] python2 ' + sys.argv[0] + ' --to-ranges 192.168.0.1 192.168.0.2 192.168.0.3 192.168.1.5 192.168.1.6 192.168.1.7')
        print('[Usage] python2 ' + sys.argv[0] + ' --to-subnets 192.168.0.1 192.168.0.2 192.168.0.3 192.168.1.5 192.168.1.6 192.168.1.7')
        sys.exit(-1)
    elif sys.argv[1] == '--to-ranges':
        args = sys.argv[2:]
        args_array = list(args)
        print(convert(merge_ip_list(args_array)).lstrip())
    elif sys.argv[1] == '--to-subnets':
        args = sys.argv[2:]
        args_array = list(args)
        for i in merge_ip_list(args_array):
            for j in list(ipaddress.summarize_address_range(ipaddress.IPv4Address(unicode(i[0], 'utf-8')), ipaddress.IPv4Address(unicode(i[1], 'utf-8')))):
                print str(j),