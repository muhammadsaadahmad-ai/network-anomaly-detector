from scapy.all import IP, TCP, UDP, ICMP

def extract_features(packet):
    """Extract numeric features from a scapy packet for ML input."""
    features = {
        "src_ip":      "",
        "dst_ip":      "",
        "src_port":    0,
        "dst_port":    0,
        "protocol":    "OTHER",
        "packet_size": len(packet),
        "flags":       "",
        "ttl":         0,
        "is_tcp":      0,
        "is_udp":      0,
        "is_icmp":     0,
        "flag_syn":    0,
        "flag_ack":    0,
        "flag_fin":    0,
        "flag_rst":    0,
        "flag_psh":    0,
    }

    if IP in packet:
        features["src_ip"]  = packet[IP].src
        features["dst_ip"]  = packet[IP].dst
        features["ttl"]     = packet[IP].ttl

    if TCP in packet:
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["protocol"] = "TCP"
        features["is_tcp"]   = 1
        tcp_flags = packet[TCP].flags
        features["flags"]    = str(tcp_flags)
        features["flag_syn"] = 1 if tcp_flags & 0x02 else 0
        features["flag_ack"] = 1 if tcp_flags & 0x10 else 0
        features["flag_fin"] = 1 if tcp_flags & 0x01 else 0
        features["flag_rst"] = 1 if tcp_flags & 0x04 else 0
        features["flag_psh"] = 1 if tcp_flags & 0x08 else 0

    elif UDP in packet:
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport
        features["protocol"] = "UDP"
        features["is_udp"]   = 1

    elif ICMP in packet:
        features["protocol"] = "ICMP"
        features["is_icmp"]  = 1

    return features

def features_to_vector(f):
    """Convert feature dict to numeric vector for ML model."""
    return [
        f["packet_size"],
        f["src_port"],
        f["dst_port"],
        f["ttl"],
        f["is_tcp"],
        f["is_udp"],
        f["is_icmp"],
        f["flag_syn"],
        f["flag_ack"],
        f["flag_fin"],
        f["flag_rst"],
        f["flag_psh"],
    ]
