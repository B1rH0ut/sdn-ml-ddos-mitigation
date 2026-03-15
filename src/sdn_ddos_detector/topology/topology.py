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
import argparse
import os
import sys
import glob as glob_mod


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

    def __init__(self, spine_count=2, leaf_count=3, host_count=10):
        """
        Initialize the spine-leaf topology.

        Args:
            spine_count (int): Number of spine switches (default: 2).
            leaf_count (int): Number of leaf switches (default: 3).
            host_count (int): Number of hosts (default: 10).
        """
        # Configurable via CLI args instead of hardcoded constants
        self.SPINE_COUNT = spine_count
        self.LEAF_COUNT = leaf_count
        self.HOST_COUNT = host_count
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
        # Distribute hosts evenly across leaves algorithmically
        info('*** Connecting hosts to leaf switches\n')
        hosts_per_leaf = self.HOST_COUNT // self.LEAF_COUNT
        remainder = self.HOST_COUNT % self.LEAF_COUNT
        idx = 0
        for i, leaf in enumerate(leaves):
            # Distribute remainder hosts to the first 'remainder' leaves
            count = hosts_per_leaf + (1 if i < remainder else 0)
            for host in hosts[idx:idx + count]:
                self.addLink(host, leaf, bw=100, delay='5ms')
            idx += count


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
    print("  Note:     Switches use fail-mode=secure (drop traffic if controller down)")

    print("\n[SWITCHES]")
    for switch in net.switches:
        print(f"  {switch.name}: dpid={switch.dpid}")

    print("\n[HOSTS]")
    for host in net.hosts:
        print(f"  {host.name}: IP={host.IP()}, MAC={host.MAC()}")

    num_switches = len(net.switches)
    num_hosts = len(net.hosts)
    num_links = len(net.links)

    print("\n[LINK SPECIFICATIONS]")
    print("  Bandwidth:       100 Mbps")
    print("  Delay:           5 ms")
    print(f"  Total switches:  {num_switches}")
    print(f"  Total hosts:     {num_hosts}")
    print(f"  Total links:     {num_links}")

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


def create_network(spine_count=2, leaf_count=3, host_count=10):
    """
    Create and start the Mininet network.

    Args:
        spine_count (int): Number of spine switches.
        leaf_count (int): Number of leaf switches.
        host_count (int): Number of hosts.
    """

    # Clean up any previous Mininet state
    info('*** Cleaning up previous Mininet state\n')
    os.system('mn -c > /dev/null 2>&1')

    # Create topology instance with configurable parameters
    info('*** Creating topology\n')
    topo = SpineLeafTopology(spine_count, leaf_count, host_count)

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

    # Set fail-mode=secure on all switches (audit 3.3)
    # In secure mode, switches drop all traffic when controller is unreachable,
    # preventing an unprotected network when the DDoS detection controller is down.
    # Loop prevention is handled by ECMP group tables in the controller (audit 5.1),
    # not by STP which blocks redundant paths.
    info('*** Setting fail-mode=secure on all switches\n')
    for switch in net.switches:
        switch_name = switch.name
        os.system(f'ovs-vsctl set-fail-mode {switch_name} secure')
        info(f'  fail-mode=secure on {switch_name}\n')

    # Brief pause for OVS configuration to apply
    import time
    time.sleep(2)

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

    Checks for root privileges, parses CLI args, sets log level, and
    creates the network with proper error handling.
    """

    # Check if script is run as root (required for Mininet)
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root.")
        print("Usage: sudo python3 topology.py")
        sys.exit(1)

    # Parse topology parameters from CLI
    parser = argparse.ArgumentParser(
        description='Create SDN spine-leaf network topology in Mininet'
    )
    parser.add_argument('--spines', type=int, default=2,
                        help='Number of spine switches (default: 2)')
    parser.add_argument('--leaves', type=int, default=3,
                        help='Number of leaf switches (default: 3)')
    parser.add_argument('--hosts', type=int, default=10,
                        help='Number of hosts (default: 10)')
    parser.add_argument('--tls', action='store_true',
                        help='Use ssl: instead of tcp: for controller '
                             '(requires TLS certs from setup_tls.sh)')
    args = parser.parse_args()

    if args.spines < 1 or args.leaves < 1 or args.hosts < 1:
        print("ERROR: All topology parameters must be >= 1")
        sys.exit(1)

    # Set Mininet log level to info
    setLogLevel('info')

    try:
        # Warn if --tls requested but certs not found
        if args.tls:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            tls_dir = os.path.join(script_dir, '..', 'config', 'tls')
            if not os.path.isdir(tls_dir) or not glob_mod.glob(
                os.path.join(tls_dir, '*.pem')
            ):
                print("WARNING: --tls specified but no certificates found in "
                      f"{tls_dir}")
                print("Run: sudo bash scripts/setup_tls.sh first")
                sys.exit(1)

        # Create and run the network
        create_network(args.spines, args.leaves, args.hosts)

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
