#!/usr/bin/python3

import socket
import re
import struct
import sys
import subprocess
import random
import uuid
import threading
from urllib.parse import urlparse

''' GLOBAL VARIABLES '''
source_IP, destination_IP = '', ''
interface = ''
source_port = random.randint(30000,50000)
destination_port = 80
tcp_data = {'sequence_no':0, 'ack_no':0, 'ack_flag':0, 'syn_flag':0, 'finish_flag':0, 'application_data':''}    # Holds the passed TCP header elements
host_name = ''
uri_name = ''
file_name = ''
index  = 0                                                                                                      # 'index' is useful during segmentation
ssthresold = 1                                                                                                  # Slow start flag. Used for congestion control



'''
    This funtion will parse the provided URL into 3 different components
    INPUT: url
    OUTPUT: Populates the host_name, uri_name, and file_name global varibales
'''
def parse_hostname_pathname(url):

    global host_name, uri_name, file_name

    if url == '':
        print("No URL provided. Program exiting.")
        sys.exit()

    if not(re.findall(r'^http://', url)):
        url = 'http://' + url

    url_elements = re.findall(r'^(http:\/\/)(.*?)(\/.*){0,}$', url)

    if not(url_elements):
        print("No URL found, please try again. Program Exiting.")
        sys.exit()

    else:
        if (len(url_elements[0]) == 2) or ((len(url_elements[0]) == 3) and url_elements[0][-1] == ''):
            file_name = 'index.html'
            uri_name = '/'
            host_name = url_elements[0][1]

        else:
            host_name = url_elements[0][1]
            uri_name = url_elements[0][2]

            if (uri_name.split('/'))[-1] == '':
                file_name = 'index.html'
            else:
                file_name = (uri_name.split('/'))[-1]

    return


'''
    This funtion will find the IP address of source machine and target machine. And will also populate the source_ip and destination_ip global variables
    INPUT: hostname
    OUTPUT: Populates source_ip and destination_ip global varibales
'''
def get_ipddr_source_dest(hostName):

    global source_IP, destination_IP

    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        udp_socket.connect(("8.8.8.8", 80))
        source_IP = udp_socket.getsockname()[0]

        ''' Collecting the destination IP '''
        destination_IP = socket.gethostbyname(hostName)
    except:
        print("An unexpected error occured while gathering source or destination IP address. Program exiting.")
        sys.exit()
    return


'''
    This funtion will generate a transmit socket which will be used through out the code.
    Address Family = AF_INET
    Type = SOCK_RAW
    Protocol = IPPROTO_RAW

    INPUT: N/A
    OUTPUT: Returns a socket object
'''
def generate_send_socket():

    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("An error occured during send_socket creation. Error: {0}\nProgram exiting.".format(e))
        sys.exit()
    return send_socket


'''
    This funtion will generate a receive socket which will be used through out the code.
    Address Family = AF_INET
    Type = SOCK_RAW
    Protocol = IPPROTO_TCP

    INPUT: N/A
    OUTPUT: Returns a socket object
'''
def generate_receive_socket():

    try:
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print("An error occured during receive_socket creation. Error: {0}\nProgram exiting.".format(e))
        sys.exit()
    return receive_socket


'''
    This funtion will collect the IP of the gateway
    INPUT: N/A
    OUTPUT: IP address of the gateway
'''
def find_gateway_ip():

    try:
        gateway_ip = (subprocess.check_output("/sbin/ip route | head -1 | cut -d ' ' -f3", shell=True)).decode('UTF-8')
    except:
        print("Error during collecting gateway IP. Please try again. Program exiting.")
        sys.exit()
    return gateway_ip.strip('\n')


'''
    This funtion will collect the interface of the source machine that we will be using
    INPUT: N/A
    OUTPUT: Populates the interface global variable
'''
def find_interface():

    global interface
    try:
        interface = ((subprocess.check_output("/sbin/ip route | head -1 | cut -d ' ' -f5", shell=True)).decode('UTF-8')).strip('\n')
    except:
        print("Error during collecting interface name. Please try again. Program exiting.")
        sys.exit()
    return


'''
    This funtion will collect MAC address of the gateway
    INPUT: N/A
    OUTPUT: Returns the MAC address of the gateway to the calling function
'''
def find_gateway_mac():

    ''' Collecting gateway MAC address '''
    try:
        gateway_mac = (subprocess.check_output("/bin/cat /proc/net/arp | grep '\\b{0}\\b' | head -1 | awk '{{print $4}}'".format(find_gateway_ip()), shell=True)).decode('UTF-8')
    except:
        print("Error during collecting gateway MAC value. Please try again. Program exiting.")
        sys.exit()
    return gateway_mac.strip('\n')


'''
    This funtion will collect source MAC address
    INPUT: N/A
    OUTPUT: Returns MAC address back to calling function
'''
def find_my_mac():

    try:
        hex_mac_address = hex(uuid.getnode())[2:]
        hex_mac_address = '0'*(12-len(hex_mac_address)) + hex_mac_address
        mac_address = ':'.join(hex_mac_address[i:i+2] for i in range(0, 12, 2))
    except:
        print("Error during collecting source hex address. Please try again. Program exiting.")
        sys.exit()
    return mac_address


'''
    This funtion will perform the TCP handshake
    INPUT: transmit_socket, receive_socket
    OUTPUT: Acknowledgement Number, MSS, Sequence Number
'''
def TCP_handshake(transmit_socket, receive_socket):

    global tcp_data

    tcp_data['sequence_no'] = 0
    tcp_data['ack_no'] = 0
    tcp_data['ack_flag'] = 0
    tcp_data['syn_flag'] = 1
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = ''

    tcp_segment, header_length = tcp_header_builder(tcp_data)
    ip_header = ip_header_build(header_length)
    packet =  ip_header + tcp_segment
    send_packet(packet, transmit_socket)
    new_ack,mss = check_ack_received(tcp_data['sequence_no'], tcp_data['ack_no'], receive_socket, 44)

    if (new_ack == False):
        print("Faliure during handshake \n")
        sys.exit()
    else:
        tcp_data['sequence_no'] = 1
        tcp_data['ack_no'] = new_ack + 1
        tcp_data['ack_flag'] = 1
        tcp_data['syn_flag'] = 0
        tcp_data['finish_flag'] = 0
        tcp_data['application_data'] = ''

        tcp_segment, header_length = tcp_header_builder(tcp_data)
        ip_header = ip_header_build(header_length)
        packet =  ip_header + tcp_segment
        send_packet(packet, transmit_socket)

        return new_ack, mss, tcp_data['sequence_no']


'''
    This funtion builds that TCP segment.
    INPUT: tcp_data, PSH_flag
    OUTPUT: TCP segment (Bytes) and header length. Header length is always 20 since we never use the optional header fields.
'''
def tcp_header_builder(data, PSH_flag=0):

    global source_port, destination_port

    sequenceNumber = data['sequence_no']
    ackNumber = data['ack_no']
    data_offset = (5 << 4) + 0
    FIN_flag, SYN_flag, RST_flag, PSH_flag, ACK_flag, URG_flag = data['finish_flag'],data['syn_flag'],0,PSH_flag,data['ack_flag'],0
    TCP_flags = FIN_flag + (SYN_flag << 1) + (RST_flag << 2) + (PSH_flag << 3) + (ACK_flag << 4) + (URG_flag << 5)
    win_size = socket.htons(1500)
    checksum = 0
    urgent_pointer = 0

    app_data_len = len(data['application_data'])

    #padding the data
    if (app_data_len%2):
        app_data_len += 1

    if data['application_data']:
        tcp_header = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNumber, ackNumber, data_offset, TCP_flags, win_size, checksum, urgent_pointer, data['application_data'].encode("iso-8859-1"))

    else:
        tcp_header = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNumber, ackNumber, data_offset, TCP_flags, win_size, checksum, urgent_pointer)


    # Creating Psuedo header

    source_address = socket.inet_aton(source_IP)
    destination_address = socket.inet_aton(destination_IP)
    reserved = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    pseudo_header = struct.pack('!4s4sBBH', source_address, destination_address, reserved, protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header
    checksum = calculate_checksum(pseudo_header)

    # Creating final TCP Header

    if data['application_data']:
        tcp_header = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNumber, ackNumber, data_offset, TCP_flags, win_size, checksum, urgent_pointer, data['application_data'].encode("iso-8859-1"))
    else:
        tcp_header = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNumber, ackNumber, data_offset, TCP_flags, win_size, checksum, urgent_pointer)

    return tcp_header,20


'''
    This funtion calculates the checksum of the supplied data
    INPUT: pseudo_header (header with certain defined fields and checksum field set to 0)
    OUTPUT: Return Checksum of the provided payload
'''
def calculate_checksum(pseudo_header):

    checksum = 0
    for i in range(0, len(pseudo_header),2):
        word = (pseudo_header[i] << 8) + (pseudo_header[i+1])
        checksum = checksum + word

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    checksum = ~(checksum) & 0xffff
    return checksum


'''
    This funtion will build the IP packet
    INPUT: payload length
    OUTPUT: Return the IP Packet (Bytes)
'''
def ip_header_build(payload_len):

    global source_IP, destination_IP

    length = 5                                                      # Header Length (20 bytes)
    version = 4                                                     # IP version (IPv4)
    version_legth = length + ( version << 4)                        # Combining length and version
    type_of_service = 0                                             # Type of service field used (Set to 0 zero never used)
    total_length = 20 + payload_len
    packet_identifier = random.randint(10000,50000)                 # Packet Identifier (A Random number)
    fragment = 0                                                    # Don't fragment
    time_to_live = 255
    protocol = socket.IPPROTO_TCP
    checksum = 0
    source_address = socket.inet_aton(source_IP)
    destination_address = socket.inet_aton(destination_IP)

    pseudo_ip_header = struct.pack('!BBHHHBBH4s4s' , version_legth, type_of_service, total_length, packet_identifier, fragment, time_to_live, protocol, checksum, source_address,destination_address)
    checksum = calculate_checksum(pseudo_ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s' , version_legth, type_of_service, total_length, packet_identifier, fragment, time_to_live, protocol, checksum, source_address,destination_address)

    return ip_header


'''
    This funtion will send the built packet on the network
    INPUT: the entire packet (IP + TCP + PAYLOAD) and transmitting socket
    OUTPUT: N/A
'''
def send_packet(packet, transmit_socket):

    global source_IP, destination_IP, source_port, destination_port

    transmit_socket.sendto(packet, (destination_IP, destination_port))

    return


'''
    This funtion will check whther an ACK was received in the incoming packet or not.
    INPUT: Sequence Number, acknowledgement number, receive sockt, and last index number of the tcp header + 1
    OUTPUT: Sequence Number and mss
'''
def check_ack_received(sequence_number, ack_number,receive_socket, max_tcp_header = 40):

    recv_packet = get_received_packet(receive_socket)
    ip_header = struct.unpack("!2sH8s4s4s", recv_packet[0:20])
    mss = 0
    unpack_arguments = "!HHLLBBHHH"

    if(max_tcp_header == 44):
        unpack_arguments = unpack_arguments + 'L'

    tcp_header = struct.unpack(unpack_arguments, recv_packet[20:max_tcp_header])

    length = ip_header[1] - 40

    if (length == 0 or length == 4):
        seq_no_recv = tcp_header[2]
        ack_no_recv = tcp_header[3]
        tcp_flags = tcp_header[5]

        if (tcp_flags == 4):
            print("Port closed on the other end. Program exiting")
            sys.exit()

        if(max_tcp_header == 44):
            mss = tcp_header[9]

        ack_flag = (tcp_flags & 16)

        if(ack_flag == 16):
            return seq_no_recv, mss

    return False, mss


'''
    This funtion will collect all the packets on the network but will select only the one intended for our machine
    INPUT: receive socket
    OUTPUT: The packet
'''
def get_received_packet(receive_socket):

    global destination_IP, source_IP, source_port, destination_port
    sourceIP = ""
    dest_port = ""

    while((sourceIP != str(destination_IP) and dest_port != str(source_port)) or (sourceIP != "" and dest_port != "")):
        recv_packet = receive_socket.recv(65565)
        ip_header=recv_packet[0:20]
        ip_header=struct.unpack("!2sH8s4s4s",ip_header)
        sourceIP=socket.inet_ntoa(ip_header[3])
        tcp_header=recv_packet[20:40]
        tcp_header=struct.unpack('!HHLLBBHHH',tcp_header)
        dest_port=str(tcp_header[1])
        destinationIP = ""
        dest_port = ""

    return recv_packet


'''
    This funtion is used to send out GET request. Even though the get request we are using isn't that big but we have added basic methods for congestion control
    INPUT: get_request (GET String), sequence number, acknowledgement number, congestion window (3 by default), mss, transmit socket, receive sockt
    OUTPUT: N/A
'''
def send_get_request(get_request, sequence_number, ack_number, congestion_window, mss, transmit_socket, receive_socket):

    global index, ssthresold, tcp_data

    last_segment = 0

    if (ssthresold == 1):
        congestion_window = 1
        ssthresold = 0

    else:
        index = index + (congestion_window * mss)
        congestion_window = min(2*congestion_window, 40)

    if (len(get_request) - index <= 0):
        return

    if (len(get_request) - index > congestion_window*mss):
        segment = get_request[index:(index + congestion_window*mss)]

    else:
        segment = get_request[index:]
        last_segment = 1

    tcp_data['sequence_no'] = sequence_number
    tcp_data['ack_no'] = ack_number + 1
    tcp_data['ack_flag'] = 1
    tcp_data['syn_flag'] = 0
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = segment
    PSH_flag = 1

    tcp_segment, header_length = tcp_header_builder(tcp_data, PSH_flag)
    ip_header = ip_header_build(header_length)
    packet = ip_header + tcp_segment
    send_packet(packet, transmit_socket)

    sequence_number_recv, mss = check_ack_received(sequence_number + congestion_window, ack_number, receive_socket)

    while((sequence_number_recv == False) and (ssthresold == 0)):
        sequence_number_recv, mss = check_ack_received(sequence_number + congestion_window, ack_number, receive_socket)

    if (last_segment == 1):
        return

    send_get_request(get_request, sequence_number + congestion_window*mss, ack_number, congestion_window, mss, transmit_socket, receive_socket)


'''
    This funtion will collect the response from the server for our GET request. It responds with ACK for every received packet, and also tears down the connect after receiving FIN signal from the server.
    INPUT: sequence number, acknowledgement number, receive_scoket, transmit_socket
    OUTPUT: sequence number, acknowledgement number, and response (Dictionary)
'''
def collect_response(sequence_number, ack_number, receive_socket, transmit_socket):

    global tcp_data

    FIN = 1
    collected_data = {}
    tear_down = 0

    while(tear_down != 1):

        receive_packet = get_received_packet(receive_socket)
        ip_header_packed = receive_packet[0:20]
        tcp_header_packed = receive_packet[20:40]

        ip_header = struct.unpack("!2sH8s4s4s", ip_header_packed)
        recv_length = ip_header[1] - 40
        tcp_header = struct.unpack("!HHLLBBHHH", tcp_header_packed)

        ACK_PSH_FIN_RST_flag = tcp_header[5]

        new_sequence_number = int(tcp_header[3])
        new_ack_number = int(tcp_header[2])

        if(recv_length != 0):
            unpack_argument = "!" + str(recv_length) + "s"
            application_segment = struct.unpack(unpack_argument, receive_packet[40:(recv_length + 40)])
            collected_data[new_ack_number] = application_segment[0]

            if(compare_checksum(receive_packet, recv_length)):
                tcp_data['sequence_no'] = new_sequence_number
                tcp_data['ack_no'] = new_ack_number + recv_length
                tcp_data['ack_flag'] = 1
                tcp_data['syn_flag'] = 0
                tcp_data['finish_flag'] = 0
                tcp_data['application_data'] = ''

                tcp_segment, header_length = tcp_header_builder(tcp_data)
                ip_packet = ip_header_build(header_length)
                packet = ip_packet + tcp_segment

                send_packet(packet, transmit_socket)

        if (ACK_PSH_FIN_RST_flag == 25) or (ACK_PSH_FIN_RST_flag == 17) or (ACK_PSH_FIN_RST_flag == 4):

            if((ACK_PSH_FIN_RST_flag == 4)):
                print("Port closed on the server end. Program Exiting")
                sys.exit()

            tear_down = 1
            tcp_data['sequence_no'] = new_sequence_number
            tcp_data['ack_no'] = new_ack_number + recv_length + 1
            tcp_data['ack_flag'] = 1
            tcp_data['syn_flag'] = 0
            tcp_data['finish_flag'] = FIN
            tcp_data['application_data'] = ''

            tcp_segment, header_length = tcp_header_builder(tcp_data)
            ip_packet = ip_header_build(header_length)
            packet = ip_packet + tcp_segment

            send_packet(packet, transmit_socket)

    return new_sequence_number, new_ack_number, collected_data


'''
    This funtion will compare the checksum of the collected packet. If they do not mactch it will return false.
    INPUT: recived packet, Application data length
    OUTPUT: True or False
'''
def compare_checksum(packet, length):

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

    return (checksum_received_packet == calculate_checksum(message))


if __name__ == '__main__':

    url = sys.argv[1]

    # Collecting the url from the argument list and parsing it to generate HOST NAME, URI PATH NAME, and FILE NAME
    parse_hostname_pathname(url)

    # Populating the SOURCE and DESTINATION IP global variables
    get_ipddr_source_dest(host_name)

    # Creating transmit_socket and receive_socket for the operation
    transmit_socket = generate_send_socket()
    receive_socket = generate_receive_socket()

    # Performing TCP handshake
    new_ack, mss, new_sequence = TCP_handshake(transmit_socket, receive_socket)

    # Creating a GET request header
    GET_request = "GET " + uri_name + " HTTP/1.1\r\n" + "Host: " + host_name + "\r\n\r\n"

    # Sending our get request
    send_get_request(GET_request, new_sequence, new_ack, 3, mss, transmit_socket, receive_socket)

    # We are collecting the response from our GET request
    new_sequence_number, new_ack_number, response_data = collect_response(new_ack, new_sequence, receive_socket, transmit_socket)

    only_response = ""

    # Sorting the response data dictionary based on acknowledgement number
    for i in sorted(response_data):
        only_response += response_data[i].decode('iso-8859-1')

    if(re.search(r'^HTTP\/\d\.\d\s200\sOK', only_response)):
        # Opening and writting the response to the file. File name depends on the URL
        with open(file_name, "w") as page:
            page.write(only_response.split('\r\n\r\n')[1])

    else:
        print("Response not 200. Program exiting")
        sys.exit()

    # Closing the sockets and the file
    transmit_socket.close()
    receive_socket.close()
    page.close()
