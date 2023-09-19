from scapy.all import rdpcap


class Pcap:
    def __init__(self, path: str):
        file = rdpcap(path)
        self.name = file.listname
        self.stats = file.stats
        self.packets = file.res

    def print(self):
        for index, packet in enumerate(self.packets):
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
            print(str(index) + "." + str(packet.wirelen))
