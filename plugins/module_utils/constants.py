VALID_IP_PROTOCOLS = ["eigrp", "egp", "icmp", "icmpv6", "igmp", "igp", "l2tp", "ospfigp", "pim", "tcp", "udp", "unspecified"]

FILTER_PORT_MAPPING = {"443": "https", "25": "smtp", "80": "http", "53": "dns", "22": "ssh", "110": "pop3", "554": "rtsp", "20": "ftpData", "ftp": "ftpData"}

VALID_ETHER_TYPES = ["arp", "fcoe", "ip", "ipv4", "ipv6", "mac_security", "mpls_ucast", "trill", "unspecified"]

# mapping dicts are used to normalize the proposed data to what the APIC expects, which will keep diffs accurate
ARP_FLAG_MAPPING = dict(arp_reply="reply", arp_request="req", unspecified="unspecified")

# ICMPv4 Types Mapping
ICMP4_MAPPING = dict(
    dst_unreachable="dst-unreach", echo="echo", echo_reply="echo-rep", src_quench="src-quench", time_exceeded="time-exceeded", unspecified="unspecified"
)

# ICMPv6 Types Mapping
ICMP6_MAPPING = dict(
    dst_unreachable="dst-unreach",
    echo_request="echo-req",
    echo_reply="echo-rep",
    neighbor_advertisement="nbr-advert",
    neighbor_solicitation="nbr-solicit",
    redirect="redirect",
    time_exceeded="time-exceeded",
    unspecified="unspecified",
)

TCP_FLAGS = dict(acknowledgment="ack", established="est", finish="fin", reset="rst", synchronize="syn", unspecified="unspecified")

SUBNET_CONTROL_MAPPING = {"nd_ra_prefix": "nd", "no_default_gateway": "no-default-gateway", "querier_ip": "querier", "unspecified": ""}

NODE_TYPE_MAPPING = {"tier_2": "tier-2-leaf", "remote": "remote-leaf-wan", "virtual": "virtual", "unspecified": "unspecified"}

SPAN_DIRECTION_MAP = {"incoming": "in", "outgoing": "out", "both": "both"}
