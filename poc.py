import datetime
import subprocess as sub
import re

# TODO config info
SNOOZE_INTERVAL = 1 * 60 * 60 # 1 hour in seconds

re_srcMAC = re.compile("[0-9a-f:]{17}(?=\s>)")
re_dstIP = re.compile("(?<=(>\s))[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}")

whitelist_MAC = set() # src MAC to ignore
whitelist_IP = set() # dst IP to ignore
confirmed_List = {} # {mac : set(IPs}
alerted_List = {} # {mac+IP : alertedTime}



# TODO  load from DB(sqlite)
whitelist_MAC = set(['44:48:c1:c7:c3:be','60:30:d4:80:6b:da','7c:04:d0:c3:6c:06'])
whitelist_IP = set(['216.58.199.14'])
confirmed_List = {'88:e9:fe:63:be:00':set(['172.217.26.138','216.58.200.78'])} 



alerted_List = {'88:e9:fe:63:be:00 216.58.200.67':'2019-07-22 00:00:00'}



ingnoreMACs = 'and ether src not ('+' and '.join(whitelist_MAC)+')' if (whitelist_MAC) else ''
ingnoreIPs = 'and dst host not ('+' and '.join(whitelist_IP)+')' if (whitelist_IP) else ''




def need_alerts(srcMAC, dstIP):
    # TODO  notification function implement
    print(datetime.datetime.now(), srcMAC, dstIP)
    if srcMAC in confirmed_List.keys() :
        if dstIP in confirmed_List[srcMAC] : return False
    mac_ip = srcMAC + ' ' + dstIP
    if mac_ip in alerted_List.keys() :
        dt = datetime.datetime.now() - datetime.datetime.strptime(alerted_List[mac_ip],'%Y-%m-%d %H:%M:%S')
        if SNOOZE_INTERVAL > dt.seconds : return False
    return True

def notification(srcMAC, dstIP):
    # TODO  notification function implement
    print('Alert!',srcMAC, dstIP)


def get_manuf(val):
    # TODO  ethernet vendor search funtion implement
    # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf
    # 상기 파일을 sqlite에 넣고 쿼리하는 방향으로 생각중
    print(val)

def get_whois(val):
    # TODO  whois ip search funtion implement
    # whois 명령으로 netname,descr,country 추출
    print(val)


# excute tcpdump and console read
p = sub.Popen(
    ['sudo'
        , 'tcpdump'
        , '-letnq'
        , 'not broadcast' 
        , 'and ip' #IPv4 only
        , 'and dst net not (10.0.0.0/8 and 172.16.0.0/12 and 192.168.0.0/16 and 127.0.0.0/8 )'  #exclude local network traffic
        , ingnoreMACs
        , ingnoreIPs
        , '-c 1000' #for test
        , 'and ether src 88:e9:fe:63:be:00' #for test
    ]
    , stdout=sub.PIPE
)

for row in iter(p.stdout.readline, b''):
    r = row.rstrip().decode('utf-8')
    srcMAC = re.search(re_srcMAC, r).group(0)
    dstIP = re.search(re_dstIP, r).group(0)
    if need_alerts(srcMAC,dstIP) : notification(srcMAC,dstIP)
    