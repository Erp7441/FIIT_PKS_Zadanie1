# Packet class
# Frame class
# YAML --> Ruamel
# Na otvorenie pcap súborov použite knižnice libpcap pre linux/BSD a winpcap pre Windows.

from FrameFactory import FrameFactory
from Pcap import Pcap

pcap_file = Pcap('./samples/eth-1.pcap')

# TODO:: Check PKS github resources and PDFs

# Pokial tato cast obsahuje 2 bajtov obsahuje EtherType ide o Ethernet II packet.
# If it is >= 1536 (0x0600) then it is an Ethernet II frame and that field is interpreted as an EtherType field.
# If it is <= 1500 it is an 802.3 frame and that field is interpreted as a Length field.
# https://notes.networklessons.com/ethernet-frame-types

pass

# Výpis všetkých rámcov v hexadecimálnom tvare postupne tak, ako boli zaznamenané v súbore.
#
# Pre každý rámec uveďte:
#
# a) Poradové číslo rámca v analyzovanom súbore.
#
# b) Dĺžku rámca v bajtoch poskytnutú pcap API, ako aj dĺžku tohto rámca prenášaného po médiu. (tieto hodnoty nemusia byť rovnaké)
#
# c) Typ rámca: Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 -- Raw).
#
# d) Pre IEEE 802.3 s LLC uviesť aj Service Access Point (SAP) napr. STP, CDP, IPX, SAP ...
#
# e) Pre IEEE 802.3 s LLC a SNAP uviesť aj PID napr. AppleTalk, CDP, DTP ...
#
# f) Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný.
#
# g)  Vo výpise jednotlivé ***bajty rámca usporiadajte po 16 v jednom riadku***. Každý riadok je ukončený znakom
# nového riadku. Pre prehľadnosť výpisu je vhodné použiť neproporcionálny (monospace) font.
#
# h)  Výstup musí byť v ***YAML***. Odporúčame použiť knižnicu Ruamel pre Python.
#
# i)  Odovzdanie do AIS do 2.10.2023 23:59
#
# j)  Riešenie tejto úlohy musí byť ***prezentované na 3. cvičení***.














# TODO:: Remove legacy code
# pcap_file.packets[0].show()


# packet = pcap_file.packets[0]

# PACKET FILEDS
# packet.fields (Frame info)
# packet.fields.type
# pcap_file.packets[0].fields_desc dict of code to type

# PACKET Wire length
# packet.wirelen (Length of packet on the wire)

# PACKET Raw info
# packet.original
    # Packet mac adresses
#
# packet_bytes = packet.original.hex()
# print(packet_bytes[0:12]) # Source MAC
# print(packet_bytes[12:24]) # Destination MAC
#
# print(packet_bytes[24:28]) # Frame Type
# # 0x0800 IP(v4), Internet Protocol version 4
# # 0x0806 ARP, Address Resolution Protocol
# # 0x8137 IPX, Internet Packet eXchange (Novell)
# # 0x86dd IPv6, Internet Protocol version 6
#
# print(packet_bytes[52:60]) # Source IP
# print(packet_bytes[60:68]) # Dest IP
#
# print(frame_lenght)

