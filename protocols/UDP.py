from handlers.FrameHandler import FrameHandler


class UDP:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def find_udp_conversations(file, app_protocol):
        udp_packets = []
        for packet in file.packets:
            try:
                if (
                        packet.ether_type == "IPv4" and
                        packet.protocol == "UDP" and
                        packet.app_protocol == "Unknown" or
                        packet.app_protocol == app_protocol
                ):
                    udp_packets.append(packet)
            except AttributeError:
                pass

        file.packets = udp_packets

        udp_conversations = []
        processed = []
        for packet in udp_packets:
            if packet in processed:
                continue

            conv = UDP._find_udp_conversation(udp_packets, packet)
            if conv is not None:
                udp_conversations.append(conv)
                for udp_packet in conv['Conversation']:
                    processed.append(udp_packet)
                continue

            processed.append(packet)

        formatted_output = UDP._sort_udp_conversations(udp_conversations)

        return formatted_output

    @staticmethod
    def _find_udp_conversation(udp_packets, init_packet):
        if init_packet.dst_port != 69:
            return {
                "Conversation": [init_packet],
                "Complete": False
            }

        # Packet mensi ako dohodnuta velkost == koniec
        ports = [init_packet.src_port]
        ip = [init_packet.dst_ip, init_packet.src_ip]

        size = 60  # Constant?
        last = False

        udp_conversation = [init_packet]

        for i, udp_packet in enumerate(udp_packets):
            if udp_packet is init_packet:
                ports.append(udp_packets[i + 1].src_port)
                continue

            if (
                    (udp_packet.src_ip in ip and udp_packet.dst_ip in ip) and
                    (udp_packet.src_port in ports and udp_packet.dst_port in ports)
            ):
                udp_conversation.append(udp_packet)

                if udp_packet.app_protocol == "Unknown":
                    udp_packet.app_protocol = init_packet.app_protocol

                opcode = int(FrameHandler.parse_tftp_opcode(udp_packet.hexa_frame), 16)
                if udp_packet.len_frame_pcap < size or opcode == 5:
                    last = True
            elif last:
                break  # Last packet of communication

        return {
            "Conversation": udp_conversation,
            "Complete": last
        }

    @staticmethod
    def _sort_udp_conversations(udp_conversations):
        formatted_output = {
            "Complete": [],
            "Incomplete": []
        }

        for num, udp_conversation in enumerate(udp_conversations):
            if udp_conversation['Complete']:
                target = "Complete"
            else:
                target = "Incomplete"

            formatted_dict = {
                "number_comm": num + 1,
                "src_comm": udp_conversation['Conversation'][0].src_ip,
                "dst_comm": udp_conversation['Conversation'][0].dst_ip,
                "packets": []
            }

            for packet in udp_conversation['Conversation']:
                formatted_dict["packets"].append(packet)

            formatted_output[target].append(formatted_dict)

        if len(formatted_output['Incomplete']) > 0:
            formatted_output['Incomplete'] = formatted_output['Incomplete'][0]
        return formatted_output
