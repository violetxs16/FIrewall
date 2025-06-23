# Controller file for firewall
from pox.core import core
import pox.openflow.libopenflow_01 as of
log = core.getLogger()
class Firewall (object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        # This binds our PacketIn event listener
        connection.addListeners(self)
    def do_firewall (self, packet, packet_in):
        # The code in here will be executed for every packet.
        if packet.find('arp'):
            # Handle packet
            packet_out = of.ofp_packet_out()
            packet_out.actions.append(of.ofp_action_output(port =
            of.OFPP_FLOOD))
            packet_out.data = packet_in
            self.connection.send(packet_out)
            # Make new rule
            match = of.ofp_match(dl_type = pkt.ethernet.ARP_TYPE)
            arp_rule = of.ofp_flow_mod()
            arp_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            arp_rule.match = match
            arp_rule.idle_timeout = of.OFP_FLOW_PERMANENT
            self.connection.send(arp_rule)
        elif packet.find('ipv4') and packet.find('tcp'):
            # Handle packet
            packet_out = of.ofp_packet_out()
            packet_out.data = packet_in
            packet_out.actions.append(of.ofp_action_output(port =
            of.OFPP_FLOOD))
            self.connection.send(packet_out)
            # Make new rule
            match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_proto =
            pkt.ipv4.TCP_PROTOCOL)
            rule = of.ofp_flow_mod()
            rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            rule.match = match
            rule.idle_timeout = of.OFP_FLOW_PERMANENT
            self.connection.send(rule)
        elif packet.find('ipv4'):
            #handle packet
            packet_out = of.ofp_packet_out()
            packet_out.data = packet_in
            # No actions = drop
            self.connection.send(packet_out)
            # Make new rule
            match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE)
            ipv4_rule = of.ofp_flow_mod()
            # No actions in rule = drop
            ipv4_rule.match = match
            ipv4_rule.idle_timeout = of.OFP_FLOW_PERMANENT
            self.connection.send(ipv4_rule)
    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
        return
            packet_in = event.ofp # The actual ofp_packet_in message.
            self.do_firewall(packet, packet_in)
def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)
        core.openflow.addListenerByName("ConnectionUp", start_switch)