# Packet class
# Frame class
# YAML --> Ruamel
# Na otvorenie pcap súborov použite knižnice libpcap pre linux/BSD a winpcap pre Windows.

from Pcap import Pcap

pcap_file = Pcap('./samples/eth-1.pcap')
pcap_file.print()