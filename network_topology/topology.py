#!/usr/bin/env python3
"""
SDN-based Spine-Leaf Network Topology

This script creates a Mininet network with a proper spine-leaf (Clos)
architecture for testing SDN-based DDoS detection and mitigation. The
network consists of 5 OpenFlow switches and 10 hosts, connected to a
remote Ryu controller.

Topology:
    - Spine layer:  2 switches (s1, s2)
    - Leaf layer:   3 switches (s3, s4, s5)
    - Full mesh:    Every leaf connects to every spine (6 inter-switch links)
    - Hosts:        10 hosts distributed across leaf switches
    - Links:        100 Mbps bandwidth, 5 ms delay

This is a true spine-leaf (Clos) topology where every leaf switch has
an uplink to every spine switch, providing equal-cost multipath routing
between any two hosts on different leaf switches.

Usage:
    sudo python3 topology.py

Requirements:
    - Mininet installed
    - OpenFlow 1.3 support
    - Ryu controller running at 127.0.0.1:6653

"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import sys


class SpineLeafTopology(Topo):
    """
    Mininet topology implementing a spine-leaf (Clos) architecture.

    A two-tier fabric where every leaf switch connects to every spine
    switch, forming a full bipartite graph between tiers. This provides
    equal-cost multipath (ECMP) between any two hosts on different
    leaf switches.

    Topology layout:

          s1 (spine)          s2 (spine)
          /   |   \\          /   |   \\
         /    |    \\        /    |    \\
       s3    s4     s5     s3    s4     s5
     (leaf) (leaf) (leaf)

       s3: h1, h2, h3         (10.0.0.1-3)
       s4: h4, h5, h6, h7     (10.0.0.4-7)
       s5: h8, h9, h10        (10.0.0.8-10)

    Attributes:
        SPINE_COUNT (int): Number of spine switches (2).
        LEAF_COUNT (int): Number of leaf switches (3).
        HOST_COUNT (int): Number of hosts (10).
    """

    SPINE_COUNT = 2
    LEAF_COUNT = 3
    HOST_COUNT = 10

    def __init__(self):
        """Initialize the spine-leaf topology."""
        super(SpineLeafTopology, self).__init__()

    def build(self):
        """
        Build the spine-leaf topology.

        Creates switches, hosts, and links:
        - 2 spine switches (s1, s2) with OpenFlow 1.3
        - 3 leaf switches (s3, s4, s5) with OpenFlow 1.3
        - 10 hosts (h1-h10) with IPs 10.0.0.1-10/24
        - 6 spine-leaf links (full mesh between tiers)
        - 10 host-leaf links
        """

        # ===== CREATE SPINE SWITCHES =====
        info('*** Adding spine switches\n')
        spines = []
        for i in range(1, self.SPINE_COUNT + 1):
            spine = self.addSwitch(f's{i}', protocols='OpenFlow13')
            spines.append(spine)

        # ===== CREATE LEAF SWITCHES =====
        info('*** Adding leaf switches\n')
        leaves = []
        for i in range(self.SPINE_COUNT + 1,
                       self.SPINE_COUNT + self.LEAF_COUNT + 1):
            leaf = self.addSwitch(f's{i}', protocols='OpenFlow13')
            leaves.append(leaf)

        # ===== CREATE HOSTS =====
        info('*** Adding hosts\n')
        hosts = []
        for i in range(1, self.HOST_COUNT + 1):
            host = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
            hosts.append(host)

        # ===== CREATE SPINE-LEAF LINKS (FULL MESH) =====
        # Every leaf connects to every spine — the defining property
        # of a spine-leaf (Clos) topology
        info('*** Creating spine-leaf full mesh links\n')
        for spine in spines:
            for leaf in leaves:
                self.addLink(spine, leaf, bw=100, delay='5ms')

        # ===== CONNECT HOSTS TO LEAF SWITCHES =====
        # Distribute 10 hosts across 3 leaf switches:
        #   s3 (leaf 0): h1, h2, h3        → 3 hosts
        #   s4 (leaf 1): h4, h5, h6, h7    → 4 hosts
        #   s5 (leaf 2): h8, h9, h10       → 3 hosts
        info('*** Connecting hosts to leaf switches\n')
        host_distribution = [
            (leaves[0], hosts[0:3]),    # s3 ← h1, h2, h3
            (leaves[1], hosts[3:7]),    # s4 ← h4, h5, h6, h7
            (leaves[2], hosts[7:10]),   # s5 ← h8, h9, h10
        ]

        for leaf, leaf_hosts in host_distribution:
            for host in leaf_hosts:
                self.addLink(host, leaf, bw=100, delay='5ms')


def print_topology_info(net):
    """
    Print detailed information about the network topology.

    Args:
        net: Mininet network instance.
    """
    print("\n" + "=" * 70)
    print("      SDN-based Spine-Leaf Network Topology")
    print("=" * 70)

    print("\n[CONTROLLER INFORMATION]")
    print("  Address:  127.0.0.1:6653")
    print("  Protocol: OpenFlow 1.3")
    print("  Note:     Network will continue even if controller is not reachable")

    print("\n[SWITCHES]")
    switches_info = [
        ("s1", "Spine switch 1"),
        ("s2", "Spine switch 2"),
        ("s3", "Leaf switch 1 — hosts h1, h2, h3"),
        ("s4", "Leaf switch 2 — hosts h4, h5, h6, h7"),
        ("s5", "Leaf switch 3 — hosts h8, h9, h10"),
    ]
    for switch, description in switches_info:
        print(f"  {switch}: {description}")

    print("\n[HOSTS]")
    for i in range(1, 11):
        host = net.get(f'h{i}')
        print(f"  h{i}: IP={host.IP()}, MAC={host.MAC()}")

    print("\n[TOPOLOGY STRUCTURE]")
    print("        s1 (spine)          s2 (spine)")
    print("        /  |  \\            /  |  \\")
    print("       /   |   \\          /   |   \\")
    print("     s3    s4    s5      s3   s4    s5")
    print("   (leaf) (leaf) (leaf)")
    print("    /|\\   /||\\   /|\\")
    print("  h1-h3  h4-h7  h8-h10")

    print("\n[LINK SPECIFICATIONS]")
    print("  Bandwidth:       100 Mbps")
    print("  Delay:           5 ms")
    print("  Spine-leaf:      6 links (full mesh)")
    print("  Host-leaf:       10 links")
    print("  Total:           16 links")

    print("\n[SPINE-LEAF PROPERTIES]")
    print("  Every leaf connects to every spine (full bipartite mesh)")
    print("  No leaf-to-leaf links (traffic always traverses a spine)")
    print("  Equal-cost multipath between hosts on different leaves")

    print("\n[USEFUL MININET COMMANDS]")
    print("  pingall              - Test connectivity between all hosts")
    print("  h1 ping h10          - Ping from h1 to h10")
    print("  dump                 - Display host information")
    print("  net                  - Display network topology")
    print("  links                - Display link information")
    print("  dpctl dump-flows     - Display OpenFlow rules")
    print("  exit                 - Stop network and exit")

    print("\n" + "=" * 70 + "\n")


def create_network():
    """
    Create and start the Mininet network.

    This function:
    1. Cleans up any previous Mininet state
    2. Creates the spine-leaf topology
    3. Initializes network with remote controller
    4. Starts the network
    5. Displays topology information
    6. Enters Mininet CLI
    7. Cleans up on exit
    """

    # Clean up any previous Mininet state
    info('*** Cleaning up previous Mininet state\n')
    os.system('mn -c > /dev/null 2>&1')

    # Create topology instance
    info('*** Creating topology\n')
    topo = SpineLeafTopology()

    # Create network with remote controller
    # Controller is expected at 127.0.0.1:6653 (default Ryu controller port)
    info('*** Creating network\n')
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name,
            ip='127.0.0.1',
            port=6653
        ),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True  # Automatically assign MAC addresses
    )

    # Start the network
    info('*** Starting network\n')
    net.start()

    info('*** Network started successfully!\n')

    # Print detailed topology information
    print_topology_info(net)

    # Enter Mininet CLI for interactive testing
    info('*** Entering Mininet CLI (type "exit" to quit)\n')
    CLI(net)

    # Stop network when CLI exits
    info('*** Stopping network\n')
    net.stop()


def main():
    """
    Main function to run the network topology.

    Checks for root privileges, sets log level, and creates the network
    with proper error handling.
    """

    # Check if script is run as root (required for Mininet)
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root.")
        print("Usage: sudo python3 topology.py")
        sys.exit(1)

    # Set Mininet log level to info
    setLogLevel('info')

    try:
        # Create and run the network
        create_network()

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n\n*** Network stopped by user (Ctrl+C)")
        print("*** Cleaning up...")
        os.system('mn -c > /dev/null 2>&1')

    except Exception as e:
        # Handle any other errors
        print(f"\n*** ERROR: {e}")
        print("*** Cleaning up...")
        os.system('mn -c > /dev/null 2>&1')
        sys.exit(1)


if __name__ == '__main__':
    main()
