#importing required modules

import socket #to create socket
import struct #to handle binary data from network connections and convert into suitable format(int ,float etc)
import textwrap # for wrapping and formatting of plain text



#unpackin ethernet frames 
def ethernet_frame(data):

      #ethernet frame : reciever(6) sender(6) type(2) payload(46-1500)
      dest_mac,src_mac,protocol = struct.unpack('! 6s 6s H',data[:14])

      return format_mac_addr(dest_mac),format_mac_addr(src_mac),socket.htons(protocol),data[14:]

      """ htons : It is done to maintain the arrangement of bytes which is sent in the network(Endianness)
      Depending upon architecture of your device,data can be arranged in the memory either in
      the big endian format or little endian format. In networking, we call the representation 
      of byte order as network byte order and in our host, it is called host byte order.
      All network byte order is in big endian format.If your host's memory computer architecture 
      is in little endian format,htons() function become necessity but in case of big endian 
      format memory architecture,it is not necessary.
      

      commonly used format characters: 
      ?: boolean
      h: short
      l: long
      i: int
      f: float
      q: long long int
      !: reverse
      s: char"""

#standard mac address format : aa:aa:aa:aa
def format_mac_addr(bytes_mac):
    two_bytes_str = map('{:02x}'.format,bytes_mac)
    mac_addr = ':'.join(two_bytes_str).upper()
    return mac_addr


#converting to a.b.c.d
def format_ipv4(addr):
      dot = "."
      return dot.join(map(str,addr))    


#printing data on multilines instead of single line
def format_data(prefix,data,size=80):
      size -= len(prefix)
      if isinstance(data,bytes):
            data = ''.join(r'\x{:02x}'.format(byte) for byte in data)

            if size % 2:
                  size -= 1

      return '\n'.join([prefix + line for line in textwrap.wrap(data,size)]) 


#unpacking ip_packet
def ip_packet(data):

      version_and_ihl = data[0]
      
      version = (version_and_ihl) >> 4  #0.5 byte ,version 0.5 byte:internet header length 
      ihl = (version_and_ihl & 15) * 4

      ttl,protocol,src_ip,des_ip = struct.unpack('! 8x B B 2x 4s 4s',data[:20]) #header info is 20 bytes long
      #print(src_ip)
      return version,ihl,ttl,protocol,format_ipv4(src_ip),format_ipv4(des_ip),data[ihl:]


#unpacking icmp packet:
#structure of icmp header : 1st byet - type 2nd byte code3-4 is checksum 4-8 data(payload)
def icmp_packet(data):

      icmp_type,code,checksum = struct.unpack('! B B H',data[:4])
      return icmp_type,code,checksum,data[4:]


#structure of tcp packet : 2 bytes source port next 2 bytes destination port
# next line : 4 bytes sequence number next line:4 bytes ack number
def tcp_packet(data):

      (src_port,dest_port,seq,ack,offset_reserved_flags) = struct.unpack('! H H L L H',data[:14]) 

      #offset :stores the number of bytes for the headers
      offset = (offset_reserved_flags >> 12)*4   #removing all 12 bits which correspond to tcp flags and reserved

      flag_urg = (offset_reserved_flags &  32) >> 5
      flag_ack = (offset_reserved_flags &  16) >> 4
      flag_psh = (offset_reserved_flags &  8) >> 3
      flag_rst = (offset_reserved_flags &  4) >> 2
      flag_syn = (offset_reserved_flags &  2) >> 1
      flag_fin = (offset_reserved_flags &  1) >> 0

      return (src_port,dest_port,seq,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:])

#npacking udp packet
def udp_packet(data):

      src_port,dest_port,size = struct.unpack('! H H 2x H',data[:8])
      return src_port,dest_port,size,data[8:]
         

#creating a raw socket
#sock_raw : ip/tcp does not process the packet and we have to manually extract headers.

def main():
      sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))  
      #ntohs : make sure it is compatible with all endians 

      while True : 
            raw_data,addr = sock.recvfrom(106)  #addr : source address
            dest_mac,src_mac,eth_protocol,data = ethernet_frame(raw_data)

            ip_packet(raw_data)
            print('\n Ethernet Frame:')
            print('\t - Destination :{}  Source :{}  Protocol:{}'.format(dest_mac,src_mac,eth_protocol))

            # eth_protocol = 8 for ipv4
            if(eth_protocol == 8 ):
                  (version,ihl,ttl,protocol,src_ip,dest_ip,data) = ip_packet(data)
                  print('\t - IPV4 PACKET : ')
                  print('\t\t - Version :{}  Header Length :{} TTL :{}'.format(version,ihl,ttl))
                  print('\t\t - Protocol :{}  Source :{}  Destination :{}'.format(protocol,src_ip,dest_ip))


                  #ip protocol id : 1 :icmp   6:tcp   17:udp

                  #icmp protocol
                  if(protocol == 1):
                        (icmp_type,code,checksum,data) = icmp_packet(data)
                        print('\t - ICMP PACKET : ')
                        print('\t\t - Type :{}  Code :{}  Checksum :{}'.format(icmp_type,code,checksum))
                        print('\t\t - Data:')
                        print(format_data('\t\t\t ',data))

                  #tcp protocol
                  elif(protocol == 6):

                        (src_port,dest_port,seq,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data) = tcp_packet(data)
                        
                        print('\t - TCP PACKET')
                        print('\t\t - Source Port :{}  Destination Port :{}'.format(src_port,dest_port))
                        print('\t\t - Sequence Number :{}  Acknowledgement Number :{}'.format(seq,ack))
                        
                        print('\t\t - FLAGS')
                        print('\t\t\t - URG :{}  ACK :{}  PSH :{}  RST :{}  SYN :{}  FIN :{}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                        
                        print('\t\t - DATA : ')
                        print(format_data('\t\t\t ',data))

                  #udp protocol
                  elif(protocol == 17):

                        (src_port,dest_port,length,data) = udp_packet(data)

                        print('\t - UDP PACKET')
                        print('\t\t - Source Port :{}  Destination Port :{}  Length :{}'.format(src_port,dest_port,length))
                        print('\t\t - DATA : ')
                        print(format_data('\t\t\t ',data))

                  #some other protocol
                  else:
                        print('\t - DATA : ')
                        print(format_data('\t\t ',data))

                         
            else:
                  print('\t - DATA : ')
                  print(format_data('\t\t ',data))


main()
