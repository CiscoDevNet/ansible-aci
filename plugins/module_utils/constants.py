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

OPFLEX_TLS_MAPPING = {"tls_v1.0": "TLSv1", "tls_v1.1": "TLSv1.1", "tls_v1.2": "TLSv1.2"}

HTTP_TLS_MAPPING = {"tls_v1.0": "TLSv1", "tls_v1.1": "TLSv1.1", "tls_v1.2": "TLSv1.2", "tls_v1.3": "TLSv1.3"}

ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING = dict(
    spine=dict(
        class_name="infraSpineAccNodePGrp",
        rn="infra/funcprof/spaccnodepgrp-{0}",
        copp_pre_filter_policy=dict(class_name="infraRsIaclSpineProfile", tn_name="tnIaclSpineProfileName"),
        bfd_ipv4_policy=dict(class_name="infraRsSpineBfdIpv4InstPol", tn_name="tnBfdIpv4InstPolName"),
        bfd_ipv6_policy=dict(class_name="infraRsSpineBfdIpv6InstPol", tn_name="tnBfdIpv6InstPolName"),
        copp_policy=dict(class_name="infraRsSpineCoppProfile", tn_name="tnCoppSpineProfileName"),
        cdp_policy=dict(class_name="infraRsSpinePGrpToCdpIfPol", tn_name="tnCdpIfPolName"),
        lldp_policy=dict(class_name="infraRsSpinePGrpToLldpIfPol", tn_name="tnLldpIfPolName"),
        usb_configuration_policy=dict(class_name="infraRsSpineTopoctrlUsbConfigProfilePol", tn_name="tnTopoctrlUsbConfigProfilePolName"),
    ),
    leaf=dict(
        class_name="infraAccNodePGrp",
        rn="infra/funcprof/accnodepgrp-{0}",
        copp_pre_filter_policy=dict(class_name="infraRsIaclLeafProfile", tn_name="tnIaclLeafProfileName"),
        bfd_ipv4_policy=dict(class_name="infraRsBfdIpv4InstPol", tn_name="tnBfdIpv4InstPolName"),
        bfd_ipv6_policy=dict(class_name="infraRsBfdIpv6InstPol", tn_name="tnBfdIpv6InstPolName"),
        copp_policy=dict(class_name="infraRsLeafCoppProfile", tn_name="tnCoppLeafProfileName"),
        cdp_policy=dict(class_name="infraRsLeafPGrpToCdpIfPol", tn_name="tnCdpIfPolName"),
        lldp_policy=dict(class_name="infraRsLeafPGrpToLldpIfPol", tn_name="tnLldpIfPolName"),
        usb_configuration_policy=dict(class_name="infraRsLeafTopoctrlUsbConfigProfilePol", tn_name="tnTopoctrlUsbConfigProfilePolName"),
    ),
)

PIM_SETTING_CONTROL_STATE_MAPPING = {"fast": "fast-conv", "strict": "strict-rfc-compliant"}

ACI_CLASS_MAPPING = dict(
    consumer={
        "class": "fvRsCons",
        "rn": "rscons-",
        "name": "tnVzBrCPName",
    },
    provider={
        "class": "fvRsProv",
        "rn": "rsprov-",
        "name": "tnVzBrCPName",
    },
    taboo={
        "class": "fvRsProtBy",
        "rn": "rsprotBy-",
        "name": "tnVzTabooName",
    },
    interface={
        "class": "fvRsConsIf",
        "rn": "rsconsIf-",
        "name": "tnVzCPIfName",
    },
    intra_epg={
        "class": "fvRsIntraEpg",
        "rn": "rsintraEpg-",
        "name": "tnVzBrCPName",
    },
)

PROVIDER_MATCH_MAPPING = dict(
    all="All",
    at_least_one="AtleastOne",
    at_most_one="AtmostOne",
    none="None",
)

CONTRACT_LABEL_MAPPING = dict(
    consumer="vzConsLbl",
    provider="vzProvLbl",
)

SUBJ_LABEL_MAPPING = dict(
    consumer="vzConsSubjLbl",
    provider="vzProvSubjLbl",
)

MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING = {"ospf_type_1": "ospf-type1", "ospf_type_2": "ospf-type2", "": ""}

MATCH_EIGRP_INTERFACE_POLICY_DELAY_UNIT_MAPPING = dict(picoseconds="pico", tens_of_microseconds="tens-of-micro")

MATCH_EIGRP_INTERFACE_POLICY_CONTROL_STATE_MAPPING = dict(bfd="bfd", nexthop_self="nh-self", passive="passive", split_horizon="split-horizon")

MATCH_TARGET_COS_MAPPING = {
    "background": "0",
    "best_effort": "1",
    "excellent_effort": "2",
    "critical_applications": "3",
    "video": "4",
    "voice": "5",
    "internetwork_control": "6",
    "network_control": "7",
    "unspecified": "unspecified",
}

MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING = dict(multicast_domain_boundary="border", strict_rfc_compliant="strict-rfc-compliant", passive="passive")

MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING = dict(none="none", md5_hmac="ah-md5")

MATCH_COLLECT_NETFLOW_RECORD_MAPPING = dict(
    bytes_counter="count-bytes",
    pkts_counter="count-pkts",
    pkt_disposition="pkt-disp",
    sampler_id="sampler-id",
    source_interface="src-intf",
    tcp_flags="tcp-flags",
    first_pkt_timestamp="ts-first",
    recent_pkt_timestamp="ts-recent",
)

MATCH_MATCH_NETFLOW_RECORD_MAPPING = dict(
    destination_ipv4_v6="dst-ip",
    destination_ipv4="dst-ipv4",
    destination_ipv6="dst-ipv6",
    destination_mac="dst-mac",
    destination_port="dst-port",
    ethertype="ethertype",
    ip_protocol="proto",
    source_ipv4_v6="src-ip",
    source_ipv4="src-ipv4",
    source_ipv6="src-ipv6",
    source_mac="src-mac",
    source_port="src-port",
    ip_tos="tos",
    unspecified="unspecified",
    vlan="vlan",
)

MATCH_SOURCE_IP_TYPE_NETFLOW_EXPORTER_MAPPING = dict(
    custom_source_ip="custom-src-ip",
    inband_management_ip="inband-mgmt-ip",
    out_of_band_management_ip="oob-mgmt-ip",
    ptep="ptep",
)

ECC_CURVE = {"P256": "prime256v1", "P384": "secp384r1", "P521": "secp521r1", "none": "none"}

THROTTLE_UNIT = dict(requests_per_second="r/s", requests_per_minute="r/m")

SSH_CIPHERS = dict(
    aes128_ctr="aes128-ctr",
    aes192_ctr="aes192-ctr",
    aes256_ctr="aes256-ctr",
    aes128_gcm="aes128-gcm@openssh.com",
    aes256_gcm="aes256-gcm@openssh.com",
    chacha20="chacha20-poly1305@openssh.com",
)

SSH_MACS = dict(
    sha1="hmac-sha1",
    sha2_256="hmac-sha2-256",
    sha2_512="hmac-sha2-512",
    sha2_256_etm="hmac-sha2-256-etm@openssh.com",
    sha2_512_etm="hmac-sha2-512-etm@openssh.com",
)

KEX_ALGORITHMS = dict(
    dh_sha1="diffie-hellman-group14-sha1",
    dh_sha256="diffie-hellman-group14-sha256",
    dh_sha512="diffie-hellman-group16-sha512",
    curve_sha256="curve25519-sha256",
    curve_sha256_libssh="curve25519-sha256@libssh.org",
    ecdh_256="ecdh-sha2-nistp256",
    ecdh_384="ecdh-sha2-nistp384",
    ecdh_521="ecdh-sha2-nistp521",
)

USEG_ATTRIBUTE_MAPPING = dict(
    vm_name=dict(attr_type="vm-name", attr_class="fvVmAttr"),
    vm_guest=dict(attr_type="guest-os", attr_class="fvVmAttr"),
    vm_host=dict(attr_type="hv", attr_class="fvVmAttr"),
    vm_id=dict(attr_type="vm", attr_class="fvVmAttr"),
    vmm_domain=dict(attr_type="domain", attr_class="fvVmAttr"),
    vm_datacenter=dict(attr_type="rootContName", attr_class="fvVmAttr"),
    vm_custom_attr=dict(attr_type="custom-label", attr_class="fvVmAttr"),
    vm_tag=dict(attr_type="tag", attr_class="fvVmAttr"),
    vm_nic=dict(attr_type="vnic", attr_class="fvVmAttr"),
    ip=dict(attr_type="ip", attr_class="fvIpAttr"),
    mac=dict(attr_type="mac", attr_class="fvMacAttr"),
)

# useg attribute operator mapping
OPERATOR_MAPPING = dict(equals="equals", contains="contains", starts_with="startsWith", ends_with="endsWith")
