# Below command will take the single entry udp.cap or tcp.cap file,
# re-write the IPs, for UDP add reversed packet, and generate Mx16 udp or tcp pcap files, espectively.
# M = 1 million in IP-IP edges. The idea is each file has 250x250 records, 250x250x16 = 1M.
# time M=1 SRC=udp.cap python3 ./gen_xm_pcap.py will generate 16 udp pcap up to 1M relationships
# time M=32 SRC=tcp.cap python3 ./gen_xm_pcap.py will generate 32x16 tcp pcap up to 32M relationships
# if module scapy is not found run pip3 install scapy
# ulimit -n to check open file (i-node) limit
# ulimit -S -n 4096 to increase open file (i-node) limit to 4096

from multiprocessing import Process
from scapy.all import *

capture = os.environ.get('SRC')

def write(pkt, file):
    wrpcap(file, pkt, append=True)  # appends packet to file

def gen_files(cap_file, m_index, n_index):
    for sip in range(1, 251):
        for dip in range(1, 251):
            for pkt in cap_file:
                pkt[IP].src = ('10.1.%d.%d' % (m_index,sip))
                pkt[IP].dst = ('10.2.%d.%d' % (n_index,dip))
                write(pkt, str('%s.%d.%d.pcap' % (capture,m_index,n_index)))
                if pkt.haslayer(UDP):
                    # two-way direction, AC will consider target active
                    pkt[IP].dst = ('10.1.%d.%d' % (m_index,sip))
                    pkt[IP].src = ('10.2.%d.%d' % (n_index,dip))
                    o_sport = pkt[UDP].sport
                    o_dport = pkt[UDP].dport
                    pkt[UDP].sport = o_dport
                    pkt[UDP].dport = o_sport
                    write(pkt, str('%s.%d.%d.pcap' % (capture,m_index,n_index)))

if __name__ == '__main__':
    pcap = rdpcap(capture)
    m_range = range(int(os.environ.get('M')))
    n_range = range(16)
    p = [[0 for n in n_range] for m in m_range]

    for m in m_range:
        for n in n_range:
            p[m][n] = Process(target=gen_files, args=(pcap, m, n))

    for m in m_range:
        for n in n_range:
            p[m][n].start()

    for m in m_range:
        for n in n_range:
            p[m][n].join()
