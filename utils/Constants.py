class Constants:

    def __new__(cls):
        raise TypeError("Static only class!")

    FRAME_TYPE_ETHERNET_II = "ETHERNET II"
    FRAME_TYPE_EOTT = "IEEE 802.3"
    FRAME_TYPE_EOTT_RAW = "IEEE 802.3 RAW"
    FRAME_TYPE_EOTT_LLC = "IEEE 802.3 LLC"
    FRAME_TYPE_EOTT_SNAP = "IEEE 802.3 LLC & SNAP"
