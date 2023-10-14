from utils.Constants import Constants


class ARP:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def find_arp_conversations(file):
        replies = []
        requests = []
        everything = []
        for packet in file.packets:
            if packet.frame_type == Constants.FRAME_TYPE_ETHERNET_II and packet.ether_type == "ARP":
                if packet.arp_opcode == 'REQUEST':
                    requests.append(packet)
                    everything.append(packet)
                elif packet.arp_opcode == 'REPLY':
                    replies.append(packet)
                    everything.append(packet)

        file.packets = everything

        arp_conversations = ARP._sort_arp_conversations(replies, requests)
        return arp_conversations

    @staticmethod
    def _sort_arp_conversations(replies, requests):
        complete = []
        complete_ungrouped = []

        # Get all request, reply pairs
        for reply in replies:
            for request in requests:
                if reply.dst_mac == request.src_mac and reply.frame_number > request.frame_number:
                    complete.append({
                        "ip_lookup": request.lookup,
                        "ip_mac_pair": ' - '.join(reply.ip_mac_pair),
                        "packets": [request, reply]
                    })
                    complete_ungrouped.append(request)
                    complete_ungrouped.append(reply)

        # Remove frames that are in pairs from the initial arrays
        for frame in complete_ungrouped:
            if frame.arp_opcode == 'REQUEST':
                requests.remove(frame)
            elif frame.arp_opcode == 'REPLY':
                replies.remove(frame)

        # Join the two arrays together and sort them out by frame number to get 'incomplete' count
        incomplete = requests + replies
        incomplete.sort(key=lambda f: f.frame_number)

        return {
            "Complete": complete,
            "Incomplete": incomplete
        }