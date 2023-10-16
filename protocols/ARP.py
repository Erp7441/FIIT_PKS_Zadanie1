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
                try:
                    requests.remove(frame)
                except ValueError:
                    pass
            elif frame.arp_opcode == 'REPLY':
                try:
                    replies.remove(frame)
                except ValueError:
                    pass

        # Join the two arrays together and sort them out by frame number to get 'incomplete' count
        incomplete = requests + replies
        if incomplete is not None and len(incomplete) > 0:
            incomplete.sort(key=lambda f: f.frame_number)
            incomplete = [{
                "packets": incomplete
            }]

        return {
            "Complete": complete,
            "Incomplete": incomplete
        }