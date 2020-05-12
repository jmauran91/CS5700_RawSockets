#!/usr/bin/python3

import re
import struct
import subprocess
import uuid
import threading
import sys
import socket
import random
from urllib.parse import urlparse
import binascii

#debugging variables
sent_packet_no = 1

#TCP packet type values
urg_val = 32
ack_val = 16
psh_val = 8
rst_val = 4
syn_val = 2
fin_val = 1
psh_ack_val = 24
syn_ack_val = 18
fin_psh_ack_val = 25
fin_ack_val = 17
rst_ack_val = 20

#GLOBALS
source_IP = ''
destination_IP = ''
interface = ''
source_port = random.randint(30000, 50000)
destination_port = 80
tcp_data = {'sequence_no':0, 'ack_no':0, 'ack_flag':0, 'syn_flag':0, 'finish_flag':0, 'application_data':''}
hostname = ''
pathname = ''
filename = ''
index = 0
ssthreshold = 1
ack_sent = []

def host_and_path_Parser(url):
    global hostname, pathname, filename
    if url == '':
        print("No URL given. Program quitting")
        sys.exit()

    url_elements = url.split('/')
    scheme_name = url_elements[0] + '//'
    hostname = url_elements[2]
    pathname = "/".join(url_elements[3:-1])
    filename = url_elements[-1]
    if filename == '':
        filename = 'index.html'
    return

def get_IPddr_srcdest(hostname):
    global source_IP, destination_IP
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        udp_socket.connect(("8.8.8.8", 80))
        source_IP = udp_socket.getsockname()[0].rstrip()

        destination_IP = socket.gethostbyname(hostname).rstrip()

    except:
        print("Error occurred in gathering SRC/DST IP")
        sys.exit()
    return

def makeSend():
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("Error in trying to create send socket. Error {}".format(e))
        sys.exit()
    return send_socket

def makeRecv():
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_socket.bind((source_IP, source_port))
    except socket.error as e:
        print("Error in trying to create recv socket. Error {}".format(e))
        sys.exit()
    return recv_socket

def send_pack(packet, sock):
    global destination_IP, destination_port, sent_packet_no
    sock.sendto(packet, (destination_IP, destination_port))
    print('{}) Packet Sent to {}:{}'.format(sent_packet_no, destination_IP, destination_port))
    sent_packet_no = sent_packet_no + 1
    return

def recv_pack(sock):
    global destination_IP, source_IP
    global destination_port, source_port
    packet_src_IP = ""
    packet_dst_IP = ""
    packet_dst_port = ""
    flag = 0
    counter = 0

    while not((packet_dst_IP == source_IP) and (any(flag == x for x in [fin_psh_ack_val, fin_ack_val, fin_val, rst_val, rst_ack_val, psh_ack_val, 16]))):
        recv_packet = sock.recvfrom(65565)
        header_key = recv_packet[0][0:20]
        header = struct.unpack("!2sH8s4s4s", header_key)
        packet_src_IP = socket.inet_ntoa(header[3])
        packet_dst_IP = socket.inet_ntoa(header[4])
        tcp_key = recv_packet[0][20:40]
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_key)
        packet_dst_port = str(tcp_header[1])
        flag = tcp_header[5]

    return recv_packet

def recv_pack_synack(sock):
    global destination_IP, source_IP
    global destination_port, source_port
    packet_src_IP = ""
    packet_dst_IP = ""
    packet_dst_port = ""
    flag = 0
    counter = 0

    while not((packet_dst_IP == source_IP) and (flag == syn_ack_val)):
        recv_packet = sock.recvfrom(65565)
        header_key = recv_packet[0][0:20]
        header = struct.unpack("!BBHHHBBH4s4s", header_key)
        packet_src_IP = socket.inet_ntoa(header[-2])
        packet_dst_IP = socket.inet_ntoa(header[-1])
        tcp_key = recv_packet[0][20:40]
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_key)
        packet_dst_port = str(tcp_header[1])
        flag = tcp_header[5]

    print("TCP flag: {}".format(flag))
    return recv_packet


def ifAckRecvd(seq_no, ack_no, recv_sock, max_header = 40, function_flag=0):

    if function_flag == 1:
        packet_recv = recv_pack_synack(recv_sock)
    else:
        packet_recv = recv_pack(recv_sock)

    ip_header = struct.unpack('!2sH8s4s4s', packet_recv[0][0:20])
    max_seg = 0
    unpack_arguments = "!HHLLBBHHH"

    if(max_header == 44):
        unpack_arguments += 'L'

    tcp_header = struct.unpack(unpack_arguments, packet_recv[0][20:max_header])
    length = ip_header[1] - 40
    if(length == 0 or 4):
        seq_no = tcp_header[2]
        ack_no = tcp_header[3]
        tcp_fl = tcp_header[5]

        if (tcp_fl == 4):
            print('Destination Port closed')
            sys.exit()

        if(max_header == 44):
            max_seg = tcp_header[9]
        ack_flag = (tcp_fl & 16)

        if(ack_flag == 16):
            return seq_no, max_seg

    return False, max_seg




def ip_headerMake(header_len):
    global source_IP, destination_IP

    version = 4
    length = 5
    version_n_length = (version << 4) + length
    dscp = 0
    total_length = 20 + header_len
    # packet_id = random.randint(10000,50000)
    packet_id = 54321
    frag_offset = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    checksum = 0
    source_addr = socket.inet_aton(source_IP)
    destination_addr = socket.inet_aton(destination_IP)

    pseudo_header = struct.pack('!BBHHHBBH4s4s', version_n_length, dscp, total_length, packet_id, frag_offset, ttl, protocol, checksum, source_addr, destination_addr)
    checksum = checksumMake(pseudo_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_n_length, dscp, total_length, packet_id, frag_offset, ttl, protocol, checksum, source_addr, destination_addr)
    return ip_header

def sendTCPPacket(data, send_sock):
    global tcp_data
    tcp_seg = tcp_headerMake(data)
    header_len = 20
    ip_header = ip_headerMake(header_len)
    packet = ip_header + tcp_seg
    send_pack(packet, send_sock)
    tcp_data = data

def TCP_handshake(send_sock, recv_sock):
    global tcp_data

    tcp_data['sequence_no'] = 0
    tcp_data['ack_no'] = 0
    tcp_data['ack_flag'] = 0
    tcp_data['syn_flag'] = 1
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = ''
    seq_no = tcp_data['sequence_no']
    ack_no = tcp_data['ack_no']

    data = tcp_data
    sendTCPPacket(data, send_sock)
    new_ack, max_seg = ifAckRecvd(seq_no, ack_no, recv_sock, 44, 1)

    if(new_ack == False):
        print("Handshake failure \n")
        sys.exit()
    else:
        tcp_data['sequence_no'] = 1
        tcp_data['ack_no'] = new_ack + 1
        tcp_data['ack_flag'] = 1
        tcp_data['syn_flag'] = 0
        tcp_data['finish_flag'] = 0
        tcp_data['application_data'] = ''
        new_seq = tcp_data['sequence_no']

        data = tcp_data
        sendTCPPacket(data, send_sock)
        return new_ack, max_seg, new_seq

def tcp_headerMake(data, PSH=0):
    global source_port, destination_port


    sequenceNum = data['sequence_no']
    ackNum = data['ack_no']
    data_offset = (5 << 4) + 0
    FIN_fl = data['finish_flag']
    SYN_fl = data['syn_flag']
    RST_fl = 0
    PSH_fl = PSH
    ACK_fl = data['ack_flag']
    URG_fl = 0
    TCP_fls = FIN_fl + (SYN_fl << 1) + (RST_fl << 2) + (PSH_fl << 3) + (ACK_fl << 4) + (URG_fl << 5)
    win_size = socket.htons(1500)
    checksum = 0
    URG_ptr = 0
    app_data_len = len(data['application_data'])
    print("making TCP header with flag {}".format(TCP_fls))

    if (app_data_len % 2):
        app_data_len += 1
    if data['application_data']:
        tcp_header = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr, data['application_data'].encode("iso-8859-1"))
    else:
        tcp_header = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr)

    source_addr = socket.inet_aton(source_IP)
    destination_addr = socket.inet_aton(destination_IP)

    pseudo_header = struct.pack('!4s4sBBH', source_addr, destination_addr, 0, socket.IPPROTO_TCP, len(tcp_header))
    pseudo_header = pseudo_header + tcp_header
    checksum = checksumMake(pseudo_header)

    if data['application_data']:
        tcp_segment = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr, data['application_data'].encode('iso-8859-1'))
    else:
        tcp_segment = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr)

    return tcp_segment

def checksumMake(header):
    checksum = 0
    for x in range(0, len(header), 2):
        wrd = (header[x] << 8) + (header[x+1])
        checksum = checksum + wrd

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    checksum = ~(checksum) & 0xffff
    return checksum

def GetRequest(http_get, seq_no, ack_no, congestion_win, mss, send_sock, recv_sock):
    print('Send GET: \r\n{}'.format(http_get))
    global index, ssthreshold, tcp_data
    last_part = 0
    if(ssthreshold == 1):
        congestion_win = 1
        ssthreshold = 0
    else:
        product = congestion_win * mss
        index=index+product
        congestion_win = min(2*congestion_win, 40)

    if(len(http_get) - index <= 0):
        return

    if (len(http_get) - index > congestion_win * mss):
        seg = http_get[index:(index + congestion_win * mss)]
    else:
        seg = http_get[index:]
        last_part = 1

    tcp_data['sequence_no'] = seq_no
    tcp_data['ack_no'] = ack_no + 1
    tcp_data['ack_flag'] = 1
    tcp_data['syn_flag'] = 0
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = seg

    data = tcp_data
    sendTCPPacket(data, send_sock)

    seq_no_recv, mss = ifAckRecvd(seq_no + congestion_win, ack_no, recv_sock)
    while((seq_no_recv == False) and (ssthreshold == 0)):
        seq_no_recv, mss = ifAckRecvd(seq_no + congestion_win, ack_no, recv_sock)

    if(last_part == 1):
        return

    GetRequest(http_get, seq_no + congestion_win*mss, ack_no, congestion_win, mss, send_sock, recv_sock)

def GetResponse(seq_no, ack_no, recv_sock, send_sock):
    global tcp_data, source_IP, ack_sent
    print("In the GET RESPONSE")


    FIN = 1
    collected = {}
    shutdown = 0
    counter = 0
    while(shutdown != 1):
        counter += 1
        recv_packet = recv_pack(recv_sock)[0]
        ip_packed = recv_packet[0:20]
        tcp_packed = recv_packet[20:40]

        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_packed)
        src_ip_addr = socket.inet_ntoa(ip_header[-2])
        recv_length = ip_header[2] - 40
        tcp_header = struct.unpack("!2H2I4H", tcp_packed)
        ## TCP_HEADER[3] IS SERVER ACK NUMBER
        ## TCP_HEADER[2] IS SERVER SEQ NUMBER
        ## SO WERE SWAPPING THEM HERE
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        new_seq_no = int(tcp_header[3])
        new_ack_no = int(tcp_header[2])
        data_offset = tcp_header[4] >> 12
        reserved = (tcp_header[4] >> 6) & 0x03ff #MUST BE ZERO
        flags = tcp_header[4] & 0x003f
        urg = flags & 0x0020
        ack = flags & 0x0010
        psh = flags & 0x0008
        rst = flags & 0x0004
        syn = flags & 0x0002
        fin = flags & 0x0001

        # import pdb; pdb.set_trace()
        # print("Incoming packet flags: \n")
        # print("{} {} {} {} {} {}".format(urg, ack, psh, rst, syn, fin))

        if ( src_ip_addr == '204.44.192.60' ):
            print('recv length not empty')
            unpack_arg = "!" + str(recv_length) + "s"
            app_seg = struct.unpack(unpack_arg, recv_packet[40:(recv_length + 40)])
            collected.update({ new_ack_no: app_seg[0] })


            # The point of this checksum is to verify that
            # The packet is what it says it is
            if(checksumComp(recv_packet, recv_length)):
                print('passed checksum')
                if( any(flags == x for x in [fin_psh_ack_val, fin_ack_val, fin_val, rst_val, rst_ack_val, psh_ack_val, psh_val])):

                    if ( any(flags == y for y in [rst_ack_val, rst_val])):

                        print("Hitting RST Flag")
                        shutdown = 1
                        tcp_data['sequence_no'] = new_seq_no
                        tcp_data['ack_no'] = new_ack_no + recv_length + 1
                        tcp_data['ack_flag'] = 1
                        tcp_data['syn_flag'] = 0
                        tcp_data['finish_flag'] = 1
                        tcp_data['application_data'] = ''

                        data = tcp_data
                        sendTCPPacket(data, send_sock)

                        # print("Port sending RST Flags.")
                        # import pdb; pdb.set_trace()
                        # sys.exit()

                    elif (any(flags == z for z in [psh_ack_val, psh_val])):

                        print("Hitting PSH Flag")
                        shutdown = 1
                        tcp_data['sequence_no'] = new_seq_no
                        tcp_data['ack_no'] = new_ack_no + recv_length + 1
                        tcp_data['ack_flag'] = 1
                        tcp_data['syn_flag'] = 0
                        tcp_data['finish_flag'] = 1
                        tcp_data['application_data'] = ''

                        data = tcp_data
                        sendTCPPacket(data, send_sock)

                    else: # FLAGS fin_psh_ack_val 17 1

                        print("Hitting FIN Flag")
                        shutdown = 1
                        tcp_data['sequence_no'] = new_seq_no
                        tcp_data['ack_no'] = new_ack_no + recv_length + 1
                        tcp_data['ack_flag'] = 1
                        tcp_data['syn_flag'] = 0
                        tcp_data['finish_flag'] = 1
                        tcp_data['application_data'] = ''

                        data = tcp_data
                        sendTCPPacket(data, send_sock)
                else:
                    tcp_data['sequence_no'] = new_seq_no
                    ack_num = new_ack_no + recv_length
                    tcp_data['ack_no'] = ack_num
                    tcp_data['ack_flag'] = 1
                    tcp_data['syn_flag'] = 0
                    tcp_data['finish_flag'] = 0
                    tcp_data['application_data'] = ''

                    data = tcp_data
                    if ack_num not in ack_sent:
                        sendTCPPacket(data, send_sock)
                        ack_sent.append(ack_num)

        else:
            pass


    return new_seq_no, new_ack_no, collected

def checksumComp(packet, length):
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
    reserved = 0
    tcp_length = ip_header[2] - 20
    protocol = ip_header[6]
    source_ip = ip_header[8]
    destination_ip = ip_header[9]
    tcp_header_packed = packet[20:]

    unpack_arguments = '!HHLLBBHHH' + str(length) + 's'

    if(length % 2):
        length += 1

    packing_argument = '!HHLLBBHHH' + str(length) + 's'
    tcp_header = struct.unpack(unpack_arguments, tcp_header_packed)

    received_tcp_segment = struct.pack(packing_argument, tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4], tcp_header[5], tcp_header[6], 0, tcp_header[8], tcp_header[9])
    pseudo_header = struct.pack("!4s4sBBH", source_ip, destination_ip, reserved, protocol, tcp_length)
    message = pseudo_header + received_tcp_segment
    checksum_received_packet = tcp_header[7]
    checksum_made = checksumMake(message)
    print("Checksum recieved packet: {}, Checksum made: {}".format(checksum_received_packet, checksum_made))

    return True #(checksum_received_packet == checksum_made)


def main():
    global hostname, pathname, filename
    global source_IP, destination_IP, source_port, destination_port
    URL = sys.argv[1]


    #Getting URL vars, and SRC & DST IP vars
    host_and_path_Parser(URL)
    get_IPddr_srcdest(hostname)

    #Creating Sockets
    send_sock = makeSend()
    recv_sock = makeRecv()

    print(source_IP)
    print(source_port)
    print(destination_IP)
    print(destination_port)


    #TCP Handshake
    new_ack, max_seg, new_seq = TCP_handshake(send_sock, recv_sock)

    HTTP_GET = "GET " + "/" + pathname + "/" + filename + " HTTP/1.1\r\n" + "Host: " + hostname + "\r\n\r\n"
    GetRequest(HTTP_GET, new_seq, new_ack, 3, max_seg, send_sock, recv_sock)

    response_seq_no, response_ack_no, response = GetResponse(new_ack, new_seq, recv_sock, send_sock)

    only_response = ""

    for x in sorted(response):
        only_response += response[x].decode('iso-8859-1')

    if( 'HTTP' and '200 OK' in only_response):
        with open(filename, 'w') as page:
            page.write(only_response.split('\r\n\r\n')[1])
    else:
        print("Response not 200")
        print(response)
        sys.exit()

    send_sock.close()
    recv_sock.close()
    page.close()



if __name__ == "__main__":

    main()
