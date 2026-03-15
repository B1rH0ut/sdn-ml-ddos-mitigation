"""Topology configuration for spine-leaf network.

Defines switch roles, port mappings, and ECMP group table parameters.
Must match the physical topology created by topology/topology.py.

Default topology (2 spine + 3 leaf, 10 hosts):
    s1, s2 = spine switches
    s3, s4, s5 = leaf switches
    s3: h1, h2, h3 (ports 1-3, uplinks 4-5)
    s4: h4, h5, h6, h7 (ports 1-4, uplinks 5-6)
    s5: h8, h9, h10 (ports 1-3, uplinks 4-5)
"""

# Spine switch datapath IDs
SPINE_DPIDS = [1, 2]

# Leaf switch datapath IDs
LEAF_DPIDS = [3, 4, 5]

# All switch DPIDs
ALL_DPIDS = SPINE_DPIDS + LEAF_DPIDS

# Leaf-to-spine uplink ports (leaf_dpid -> list of ports connected to spines)
# In the Mininet topology, leaf ports are assigned as:
#   first N ports = hosts, remaining ports = spine uplinks
LEAF_TO_SPINE_PORTS = {
    3: [4, 5],   # s3: ports 4,5 connect to s1,s2
    4: [5, 6],   # s4: ports 5,6 connect to s1,s2
    5: [4, 5],   # s5: ports 4,5 connect to s1,s2
}

# Host-facing ports per leaf switch
HOST_PORTS = {
    3: [1, 2, 3],      # s3: h1, h2, h3
    4: [1, 2, 3, 4],   # s4: h4, h5, h6, h7
    5: [1, 2, 3],      # s5: h8, h9, h10
}

# ECMP group table IDs
# GROUP_ECMP_BASE + dpid = ECMP group for that leaf's spine uplinks
GROUP_ECMP_BASE = 100

# Broadcast group table IDs
# GROUP_BCAST_BASE + dpid = broadcast group for that leaf
GROUP_BCAST_BASE = 200

# Priority structure (audit 5.3):
# Forwarding uses L2 (eth_src, eth_dst) for speed; blocking uses L3 (ipv4_src)
# for attacker targeting. Higher-priority blocks always override forwarding.
PRIORITY_BLOCK = 100        # DDoS block rules (cookie=0xDEAD)
PRIORITY_ANTI_SPOOF = 50    # Anti-spoofing rules
PRIORITY_FORWARDING = 10    # Learned forwarding / ECMP
PRIORITY_ARP_PROXY = 5      # ARP proxy rules
PRIORITY_TABLE_MISS = 0     # Table-miss -> controller

# Block rule cookie for identification and bulk deletion
BLOCK_COOKIE = 0xDEAD

# Flow table capacity thresholds
FLOW_TABLE_WARNING_PCT = 0.80    # Log warning at 80%
FLOW_TABLE_CRITICAL_PCT = 0.95   # Emergency eviction at 95%
FLOW_TABLE_CHECK_INTERVAL = 30   # Seconds between checks
FLOW_TABLE_DEFAULT_MAX = 2000    # Default max entries (OVS default varies)
