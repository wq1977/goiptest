#!/usr/bin/python
import sys,random,threading
import urllib2

allip=[]
print "Calc all ips..."

def ImportIpv4Range(ipdef):
    global allip
    vs=ipdef.split(".")
    addrdef=[]
    for s in vs:
        vss=s.split("-")
        if len(vss)==2:
            addrdef.append([int(vss[0]),int(vss[1])+1])
        else:
            addrdef.append([int(vss[0]),int(vss[0])+1])
    for ip1 in range(addrdef[0][0],addrdef[0][1]):
        for ip2 in range(addrdef[1][0],addrdef[1][1]):
            for ip3 in range(addrdef[2][0],addrdef[2][1]):
                for ip4 in range(addrdef[3][0],addrdef[3][1]):
                    allip.append("%d.%d.%d.%d" % (ip1,ip2,ip3,ip4))

ImportIpv4Range("1.179.248-255.0-255")
ImportIpv4Range("103.246.187.0-255")
ImportIpv4Range("103.25.178.4-59")
ImportIpv4Range("106.162.192.148-187")
ImportIpv4Range("106.162.198.84-123")
ImportIpv4Range("106.162.216.20-123")
ImportIpv4Range("107.167.160-191.0-255")
ImportIpv4Range("107.178.192-255.0-255")
ImportIpv4Range("107.188.128-255.0-255")
ImportIpv4Range("108.170.192-255.0-255")
ImportIpv4Range("108.177.0-127.0-255")
ImportIpv4Range("108.59.80-95.0-255")
ImportIpv4Range("109.232.83.64-127")
ImportIpv4Range("111.168.255.20-187")
ImportIpv4Range("111.92.162.4-59")
ImportIpv4Range("113.197.105-106.0-255")
ImportIpv4Range("118.174.24-27.0-255")
ImportIpv4Range("12.216.80.0-255")
ImportIpv4Range("121.78.74.68-123")
ImportIpv4Range("123.205.250-251.68-190")
ImportIpv4Range("130.211.0-255.0-255")
ImportIpv4Range("130.211.0-255.0-255")
ImportIpv4Range("142.250-251.0-255.0-255")
ImportIpv4Range("146.148.0-127.0-255")
ImportIpv4Range("149.126.86.1-59")
ImportIpv4Range("149.3.177.0-255")
ImportIpv4Range("162.216.148-151.0-255")
ImportIpv4Range("162.222.176-183.0-255")
ImportIpv4Range("163.28.116.1-59")
ImportIpv4Range("163.28.83.143-187")
ImportIpv4Range("172.217.0-255.0-255")
ImportIpv4Range("172.253.0-255.0-255")
ImportIpv4Range("173.194.0-255.0-255")
ImportIpv4Range("173.255.112-127.0-255")
ImportIpv4Range("178.45.251.4-123")
ImportIpv4Range("178.60.128.1-63")
ImportIpv4Range("185.25.28-29.0-255")
ImportIpv4Range("192.119.16-31.0-255")
ImportIpv4Range("192.158.28-31.0-255")
ImportIpv4Range("192.178-179.0-255.0-255")
ImportIpv4Range("192.200.224-255.0-255")
ImportIpv4Range("193.120.166.64-127")
ImportIpv4Range("193.134.255.0-255")
ImportIpv4Range("193.142.125.0-255")
ImportIpv4Range("193.186.4.0-255")
ImportIpv4Range("193.192.226.128-191")
ImportIpv4Range("193.192.250.128-191")
ImportIpv4Range("193.200.222.0-255")
ImportIpv4Range("193.247.193.0-255")
ImportIpv4Range("193.90.147.0-123")
ImportIpv4Range("193.92.133.0-63")
ImportIpv4Range("194.100.132.128-143")
ImportIpv4Range("194.110.194.0-255")
ImportIpv4Range("194.78.20.16-31")
ImportIpv4Range("194.78.99.0-255")
ImportIpv4Range("195.100.224.112-127")
ImportIpv4Range("195.141.3.24-27")
ImportIpv4Range("195.205.170.64-79")
ImportIpv4Range("195.229.194.88-95")
ImportIpv4Range("195.244.106.0-255")
ImportIpv4Range("195.244.120.144-159")
ImportIpv4Range("195.249.20.192-255")
ImportIpv4Range("195.65.133.128-135")
ImportIpv4Range("195.76.16.136-143")
ImportIpv4Range("195.81.83.176-207")
ImportIpv4Range("196.3.58-59.0-255")
ImportIpv4Range("197.199.253-254.1-59")
ImportIpv4Range("197.84.128.0-63")
ImportIpv4Range("199.192.112-115.0-255")
ImportIpv4Range("199.223.232-239.0-255")
ImportIpv4Range("202.39.143.1-123")
ImportIpv4Range("203.116.165.129-255")
ImportIpv4Range("203.117.34-37.132-187")
ImportIpv4Range("203.165.13-14.210-251")
ImportIpv4Range("203.211.0.4-59")
ImportIpv4Range("203.66.124.129-251")
ImportIpv4Range("207.223.160-175.0-255")
ImportIpv4Range("208.117.224-255.0-255")
ImportIpv4Range("208.65.152-155.0-255")
ImportIpv4Range("209.85.128-255.0-255")
ImportIpv4Range("210.139.253.20-251")
ImportIpv4Range("210.153.73.20-123")
ImportIpv4Range("210.242.125.20-59")
ImportIpv4Range("210.61.221.65-187")
ImportIpv4Range("212.154.168.224-255")
ImportIpv4Range("212.162.51.64-127")
ImportIpv4Range("212.181.117.144-159")
ImportIpv4Range("212.188.10.0-255")
ImportIpv4Range("212.188.15.0-255")
ImportIpv4Range("212.188.7.0-255")
ImportIpv4Range("213.186.229.0-63")
ImportIpv4Range("213.187.184.68-71")
ImportIpv4Range("213.240.44.0-31")
ImportIpv4Range("213.252.15.0-31")
ImportIpv4Range("213.31.219.80-87")
ImportIpv4Range("216.21.160-175.0-255")
ImportIpv4Range("216.239.32-63.0-255")
ImportIpv4Range("216.58.192-223.0-255")
ImportIpv4Range("217.149.45.16-31")
ImportIpv4Range("217.163.7.0-255")
ImportIpv4Range("217.193.96.38")
ImportIpv4Range("217.28.250.44-47")
ImportIpv4Range("217.28.253.32-33")
ImportIpv4Range("217.30.152.192-223")
ImportIpv4Range("217.33.127.208-223")
ImportIpv4Range("218.176.242.4-251")
ImportIpv4Range("218.189.25.129-187")
ImportIpv4Range("218.253.0.76-187")
ImportIpv4Range("23.228.128-191.0-255")
ImportIpv4Range("23.236.48-63.0-255")
ImportIpv4Range("23.251.128-159.0-255")
ImportIpv4Range("23.255.128-255.0-255")
ImportIpv4Range("24.156.131.0-255")
ImportIpv4Range("31.209.137.0-255")
ImportIpv4Range("31.7.160.192-255")
ImportIpv4Range("37.228.69.0-63")
ImportIpv4Range("41.206.96.1-251")
ImportIpv4Range("41.84.159.12-30")
ImportIpv4Range("60.199.175.1-187")
ImportIpv4Range("61.219.131.65-251")
ImportIpv4Range("62.0.54.64-127")
ImportIpv4Range("62.1.38.64-191")
ImportIpv4Range("62.116.207.0-63")
ImportIpv4Range("62.197.198.193-251")
ImportIpv4Range("62.20.124.48-63")
ImportIpv4Range("62.201.216.196-251")
ImportIpv4Range("63.243.168.0-255")
ImportIpv4Range("64.15.112-127.0-255")
ImportIpv4Range("64.233.160-191.0-255")
ImportIpv4Range("64.9.224-255.0-255")
ImportIpv4Range("66.102.0-15.0-255")
ImportIpv4Range("66.185.84.0-255")
ImportIpv4Range("66.249.64-95.0-255")
ImportIpv4Range("69.17.141.0-255")
ImportIpv4Range("70.32.128-159.0-255")
ImportIpv4Range("72.14.192-255.0-255")
ImportIpv4Range("74.125.0-255.0-255")
ImportIpv4Range("77.109.131.208-223")
ImportIpv4Range("77.40.222.224-231")
ImportIpv4Range("77.42.248-255.0-255")
ImportIpv4Range("77.66.9.64-123")
ImportIpv4Range("78.8.8.176-191")
ImportIpv4Range("8.15.202.0-255")
ImportIpv4Range("8.22.56.0-255")
ImportIpv4Range("8.34.208-223.0-255")
ImportIpv4Range("8.35.192-207.0-255")
ImportIpv4Range("8.6.48-55.0-255")
ImportIpv4Range("8.8.4.0-255")
ImportIpv4Range("8.8.8.0-255")
ImportIpv4Range("80.227.152.32-39")
ImportIpv4Range("80.228.65.128-191")
ImportIpv4Range("80.231.69.0-63")
ImportIpv4Range("80.239.168.192-255")
ImportIpv4Range("80.80.3.176-191")
ImportIpv4Range("81.175.29.128-191")
ImportIpv4Range("81.93.175.232-239")
ImportIpv4Range("82.135.118.0-63")
ImportIpv4Range("83.100.221.224-255")
ImportIpv4Range("83.141.89.124-127")
ImportIpv4Range("83.145.196.128-191")
ImportIpv4Range("83.220.157.100-103")
ImportIpv4Range("83.94.121.128-255")
ImportIpv4Range("84.233.219.144-159")
ImportIpv4Range("84.235.77.1-251")
ImportIpv4Range("85.182.250.0-191")
ImportIpv4Range("86.127.118.128-191")
ImportIpv4Range("87.244.198.160-191")
ImportIpv4Range("88.159.13.192-255")
ImportIpv4Range("89.207.224-231.0-255")
ImportIpv4Range("89.96.249.160-175")
ImportIpv4Range("92.45.86.16-31")
ImportIpv4Range("93.123.23.1-59")
ImportIpv4Range("93.183.211.192-255")
ImportIpv4Range("93.94.217-218.0-31")
ImportIpv4Range("94.200.103.64-71")
ImportIpv4Range("94.40.70.0-63")
ImportIpv4Range("95.143.84.128-191")
#ip range
ImportIpv4Range("61.19.1-2.0-127")
ImportIpv4Range("61.19.8.0-127")
ImportIpv4Range("113.21.24.0-127")
#thx for alienwaresky
ImportIpv4Range("118.143.88.16-123")
ImportIpv4Range("202.86.162.20-187")
ImportIpv4Range("139.175.107.20-187")
ImportIpv4Range("223.26.69.16-59")
ImportIpv4Range("220.255.5-6.20-251")
ImportIpv4Range("202.65.246.84-123")
ImportIpv4Range("103.1.139.148-251")
ImportIpv4Range("116.92.194.148-187")
ImportIpv4Range("58.145.238.20-59")

ImportIpv4Range("41.201.128.20-59")
ImportIpv4Range("41.201.164.20-59")
ImportIpv4Range("222.255.120.15-59")
#odns
ImportIpv4Range("119.81.145.120-127")
ImportIpv4Range("119.81.142.202")
ImportIpv4Range("23.239.5.106")
ImportIpv4Range("74.207.242.141")
ImportIpv4Range("91.213.30.143-187")




import struct

class Packet(object):

    """Creates ICMPv4 and v6 packets.
    
    header
        two-item sequence containing the type and code of the packet,
        respectively.
    version
        Automatically set to version of protocol being used or None if ambiguous.
    data
        Contains data of the packet.  Can only assign a subclass of basestring
        or None.

    packet
        binary representation of packet.
    
    """

    header_table = {
                0 : (0, 4),
                #3 : (15, 4),  Overlap with ICMPv6
                3 : (15, None),
                #4 : (0, 4),  Deprecated by RFC 1812
                5 : (3, 4),
                8 : (0, 4),
                9 : (0, 4),
                10: (0, 4),
                11: (1, 4),
                12: (1, 4),
                13: (0, 4),
                14: (0, 4),
                15: (0, 4),
                16: (0, 4),
                17: (0, 4),
                18: (0, 4),

                1 : (4, 6),
                2 : (0, 6),
                #3 : (2, 6),  Overlap with ICMPv4
                #4 : (2, 6),  Type of 4 in ICMPv4 is deprecated
                4 : (2, None),
                128: (0, 6),
                129: (0, 6),
                130: (0, 6),
                131: (0, 6),
                132: (0, 6),
                133: (0, 6),
                134: (0, 6),
                135: (0, 6),
                136: (0, 6),
                137: (0, 6),
             }

    def _setheader(self, header):
        """Set type, code, and version for the packet."""
        if len(header) != 2:
            raise ValueError("header data must be in a two-item sequence")
        type_, code = header
        try:
            max_range, version = self.header_table[type_]
        except KeyError:
            raise ValueError("%s is not a valid type argument" % type_)
        else:
            if code > max_range:
                raise ValueError("%s is not a valid code value for type %s" %\
                                     (type_, code))
            self._type, self._code, self._version = type_, code, version

    header = property(lambda self: (self._type, self._code), _setheader,
                       doc="type and code of packet")

    version = property(lambda self: self._version,
                        doc="Protocol version packet is using or None if "
                            "ambiguous")

    def _setdata(self, data):
        """Setter for self.data; will only accept a basestring or None type."""
        if not isinstance(data, basestring) and not isinstance(data, type(None)):
            raise TypeError("value must be a subclass of basestring or None, "
                            "not %s" % type(data))
        self._data = data

    data = property(lambda self: self._data, _setdata,
                    doc="data contained within the packet")

    def __init__(self, header=(None, None), data=None):
        """Set instance attributes if given."""
        #XXX: Consider using __slots__
        # self._version initialized by setting self.header
        self.header = header
        self.data = data

    def __repr__(self):
        return "<ICMPv%s packet: type = %s, code = %s, data length = %s>" % \
                (self.version, self.type, self.code, len(self.data))

    def create(self):
        """Return a packet."""
        # Kept as a separate method instead of rolling into 'packet' property so
        # as to allow passing method around without having to define a lambda
        # method.
        args = [self.header[0], self.header[1], 0]
        pack_format = "!BBH"
        if self.data:
            pack_format += "%ss" % len(self.data)
            args.append(self.data)
        # ICMPv6 has the IP stack calculate the checksum
        # For ambiguous cases, just go ahead and calculate it just in case
        if self.version == 4 or not self.version:
            args[2] = self._checksum(struct.pack(pack_format, *args))
        return struct.pack(pack_format, *args)

    packet = property(create,
                       doc="Complete ICMP packet")

    def _checksum(self, checksum_packet):
        """Calculate checksum"""
        byte_count = len(checksum_packet)
        #XXX: Think there is an error here about odd number of bytes
        if byte_count % 2:
            odd_byte = ord(checksum_packet[-1])
            checksum_packet = checksum_packet[:-1]
        else:
            odd_byte = 0
        two_byte_chunks = struct.unpack("!%sH" % (len(checksum_packet)/2),
                                        checksum_packet)
        total = 0
        for two_bytes in two_byte_chunks:
            total += two_bytes
        else:
            total += odd_byte
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF
        
    def parse(cls, packet):
        """Parse ICMP packet and return an instance of Packet"""
        string_len = len(packet) - 4 # Ignore IP header
        pack_format = "!BBH"
        if string_len:
            pack_format += "%ss" % string_len
        unpacked_packet = struct.unpack(pack_format, packet)
        type, code, checksum = unpacked_packet[:3]
        try:
            data = unpacked_packet[3]
        except IndexError:
            data = None
        return cls((type, code), data)

    parse = classmethod(parse)


#------------
# ping.py
#------------

import struct,socket,sys,time, os

datalen = 56
BUFSIZE = 1500


def ping(addr, total):
    #addr="220.181.94.203"
    ## create socket
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,
                        socket.getprotobyname('icmp'))
    s.connect((addr,22))

    ## setuid back to normal user
    os.setuid(os.getuid())

    seq_num = 0
    packet_count = 0
    process_id = os.getpid()
    base_packet = Packet((8,0))

    validtime=[]
    while total>0:
    ## create ping packet 
        seq_num += 1
        pdata = struct.pack("!HHd",process_id,seq_num,time.time())
    
    ## send initial packet 
        base_packet.data = pdata
        s.send(base_packet.packet)
    
        ## recv packet
        s.settimeout(2)
        try:
            buf = s.recv(BUFSIZE)
        except:
            total-=1
            continue
        current_time = time.time()

        ## parse packet; remove IP header first
        r = Packet.parse(buf[20:])

        ## parse ping data
        (ident,seq,timestamp) = struct.unpack("!HHd",r.data)

        ## calculate rounttrip time
        rtt =  current_time - timestamp
        rtt *= 1000
        validtime.append(rtt)
        time.sleep(1)
        total-=1
    return validtime
        
def testSocket(ip):
    ts=ping(ip,2)
    if len(ts)==2:
        return (ts[0]+ts[1])/2
    return -1;

def testHttp(ip):
    #ip="116.92.194.148"
    start=time.time()
    try:
        response = urllib2.urlopen("https://%s/" % (ip),timeout=2)
    except:
        return -1
    if (response.getcode()==200):
        return time.time()-start
    return -1

def threadTestAll(ip):
    v1=testSocket(ip)
    if v1!=-1:
        v2=testHttp(ip)
        if v2==-1:
            return
    else:
        return
    global allgoodip, mutex
    mutex.acquire()
    allgoodip[ip]=v1+v2
    mutex.release()
    print "found good ip %s:%d" % (ip,allgoodip[ip])

print "Done, total defined %d ip(s)" % (len(allip))
print "randomize look for useful ip,press CTRL+C to stop..."

allgoodip={}
TEST_COUNT_SAME_TIME=5
mutex = threading.Lock()
user_ask_quit=False
while len(allip)>0 and not user_ask_quit:
    threads=[]
    for i in range(TEST_COUNT_SAME_TIME):
        ip=random.choice(allip)
        allip.remove(ip)
        print "test ip(%d):%s" % (len(allgoodip),ip)
        threads.append(threading.Thread(target=threadTestAll, args=(ip,)))
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()   
    except:
        break

ips=sorted(allgoodip, key=allgoodip.__getitem__)
print "|".join(ips)

