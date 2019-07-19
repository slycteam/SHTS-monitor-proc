import subprocess as sub
import re



re_srcMAC = re.compile("[0-9a-f:]{17}(?=\s>)")
re_trgIP = re.compile("(?<=(>\s))[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}")

whitelist_MAC = set() # src MAC to ignore
whitelist_IP = set() # dst IP to ignore
confirmed_List = {} # {mac : set(IPs}
alerted_List = {} # {mac+IP : alertedTime}


# TODO  load from DB(sqlite)
whitelist_MAC = set(['44:48:c1:c7:c3:be','60:30:d4:80:6b:da','7c:04:d0:c3:6c:06'])
whitelist_IP = set(['216.58.199.14'])
confirmed_List = {'88:e9:fe:63:be:00':set(['125.209.230.135'])} # {mac : set(IPs)}






ingnoreMACs = 'and ether src not ('+' and '.join(whitelist_MAC)+')' if (whitelist_MAC) else ''
ingnoreIPs = 'and dst host not ('+' and '.join(whitelist_IP)+')' if (whitelist_IP) else ''

p = sub.Popen(
    ['sudo'
        , 'tcpdump'
        , '-letnq'
        , 'not broadcast' 
        , ingnoreMACs
        , ingnoreIPs
        , '-c 100' #for test
    ]
    , stdout=sub.PIPE
)

for row in iter(p.stdout.readline, b''):
    # TODO  checking tcpdump results
    print (row.rstrip())
    
    
    
def notification(val):
    # TODO  notification function implement
    print(val)

def get_manuf(val):
    # TODO  ethernet vendor search funtion implement
    # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf
    # 상기 파일을 sqlite에 넣고 쿼리하는 방향으로 생각중
    print(val)

def get_whois(val):
    # TODO  whois ip search funtion implement
    # whois 명령으로 netname,descr,country 추출
    print(val)
