VALID_IP_PROTOCOLS = ["eigrp", "egp", "icmp", "icmpv6", "igmp", "igp", "l2tp", "ospfigp", "pim", "tcp", "udp", "unspecified"]

FILTER_PORT_MAPPING = {"443": "https", "25": "smtp", "80": "http", "53": "dns", "110": "pop3", "554": "rtsp", "20": "ftpData", "ftp": "ftpData"}

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
SUBNET_CONTROL_MAPPING_BD_SUBNET = {"nd_ra": "nd", "no_gw": "no-default-gateway", "querier_ip": "querier", "unspecified": ""}

NODE_TYPE_MAPPING = {"tier_2": "tier-2-leaf", "remote": "remote-leaf-wan", "virtual": "virtual", "unspecified": "unspecified"}

SPAN_DIRECTION_MAP = {"incoming": "in", "outgoing": "out", "both": "both"}

MATCH_TYPE_MAPPING = {"all": "All", "at_least_one": "AtleastOne", "at_most_one": "AtmostOne", "none": "None"}

IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"

VM_PROVIDER_MAPPING = dict(
    cloudfoundry="CloudFoundry",
    kubernetes="Kubernetes",
    microsoft="Microsoft",
    openshift="OpenShift",
    openstack="OpenStack",
    redhat="Redhat",
    vmware="VMware",
)

MATCH_TYPE_GROUP_MAPPING = {"all": "ALL", "all_in_pod": "ALL_IN_POD", "range": "range"}

MATCH_FC_FILL_PATTERN_MAPPING = {"arbff": "ARBFF", "idle": "IDLE"}

MATCH_FIRMWARE_NODES_TYPE_MAPPING = {
    "c_apic_patch": "cApicPatch",
    "catalog": "catalog",
    "config": "config",
    "controller": "controller",
    "controller_patch": "controllerPatch",
    "plugin": "plugin",
    "plugin_package": "pluginPackage",
    "switch": "switch",
    "switch_patch": "switchPatch",
    "vpod": "vpod",
}

MATCH_TRIGGER_MAPPING = {
    "trigger": "trigger",
    "trigger_immediate": "trigger-immediate",
    "triggered": "triggered",
    "untriggered": "untriggered",
}

INTERFACE_POLICY_FC_SPEED_LIST = ["auto", "unknown", "2G", "4G", "8G", "16G", "32G"]

MATCH_RUN_MODE_MAPPING = dict(
    pause_always_between_sets="pauseAlwaysBetweenSets",
    pause_only_on_failures="pauseOnlyOnFailures",
    pause_never="pauseNever",
)

MATCH_NOTIFY_CONDITION_MAPPING = dict(
    notify_always_between_sets="notifyAlwaysBetweenSets",
    notify_never="notifyNever",
    notify_only_on_failures="notifyOnlyOnFailures",
)

MATCH_SMU_OPERATION_MAPPING = dict(smu_install="smuInstall", smu_uninstall="smuUninstall")

MATCH_SMU_OPERATION_FLAGS_MAPPING = dict(smu_reload_immediate="smuReloadImmediate", smu_reload_skip="smuReloadSkip")

MATCH_BEST_PATH_CONTROL_MAPPING = dict(enable="asPathMultipathRelax", disable="")

MATCH_GRACEFUL_RESTART_CONTROLS_MAPPING = dict(helper="helper", complete="")

EP_LOOP_PROTECTION_ACTION_MAPPING = {"bd": "bd-learn-disable", "port": "port-disable"}

FABRIC_POD_SELECTOR_TYPE_MAPPING = dict(all="ALL", range="range")

TLS_MAPPING = {"tls_v1.0": "TLSv1", "tls_v1.1": "TLSv1.1", "tls_v1.2": "TLSv1.2"}
