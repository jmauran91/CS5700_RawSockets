#sharkparse


import sys

packetno = []
srcIP = []
dstIP = []
seqno = []
ackno = []
infomsg = []


def writeLine(fw, no):
    global packetno, srcIP, dstIP, seqno, ackno, infomsg
    fw.write(str(packetno[no]))
    fw.write('\t')
    fw.write('From')
    fw.write(' ')
    fw.write(str(srcIP[no]))
    fw.write(' ')
    fw.write('\t')
    fw.write('To')
    fw.write(' ')
    fw.write(str(dstIP[no]))
    fw.write(' ')
    fw.write('\t')
    fw.write('Seq')
    fw.write(' ')
    fw.write(str(seqno[no]))
    fw.write('\t')
    fw.write(' ')

    fw.write('\t')
    fw.write('Ack')
    fw.write(' ')

    fw.write(str(ackno[no]))
    fw.write('\t')
    fw.write(' ')
    fw.write('\t')
    fw.write('Info')
    fw.write('\t')
    try:
        fw.write(infomsg[no])
    except:
        pass



def main():
    rawshark = sys.argv[1]
    output = sys.argv[2]
    global packetno, srcIP, dstIP, seqno, ackno, infomsg
    fr = open(rawshark, 'r')
    fr_lines = fr.readlines()
    counter = 0
    for line in fr_lines:
        # import pdb; pdb.set_trace()
        if "Source: 20" in line:
            ##
            counter +=1
            packetno.append(counter)
            ##
            fr_src = line.split(':')[1].rstrip()
            srcIP.append(fr_src)
        if "Destination: 20" in line:
            fr_dst = line.split(':')[1].rstrip()
            dstIP.append(fr_dst)
        if "Sequence number (raw): " in line:
            fr_seq = line.split(':')[1].rstrip()
            seqno.append(fr_seq)
        if "Acknowledgment number (raw): " in line:
            fr_ack = line.split(':')[1].rstrip()
            ackno.append(fr_ack)
        if "Seq=" in line or "HTTP" in line:
            # import pdb; pdb.set_trace()
            if not "HTTP" in line:
                if "TCP" in line:
                    if "[TCP" in line:
                        fr_inf = "TCP" + "TCP".join(line.split('TCP',2)[1:]).rstrip()
                        infomsg.append(fr_inf)
                    else:
                        fr_inf = "TCP" + "TCP".join(line.split('TCP',1)[1:]).rstrip()
                        infomsg.append(fr_inf)
            else:
                if "[TCP" in line:
                    fr_inf = "HTTP" + "".join(line.rsplit('HTTP',1)[1:]).rstrip()
                    infomsg.append(fr_inf)
                else:
                    if "GET" in line:
                        fr_inf = "HTTP" + "".join(line.rsplit("HTTP",2)[1:]).rstrip()
                        infomsg.append(fr_inf)
                    elif "Continuation" in line:
                        # import pdb; pdb.set_trace()
                        fr_inf = "HTTP" + "".join(line.rsplit('HTTP',1)[1:]).rstrip()
                        infomsg.append(fr_inf)
                    else:
                        # import pdb; pdb.set_trace()
                        fr_inf = "".join(line.split('GET')[1:]).rstrip()
                        infomsg.append(fr_inf)

    with open(output, 'w') as fw:
        for i in range(0, counter):
            writeLine(fw, i)
            fw.write('\n')


if __name__ == "__main__":
    main()
