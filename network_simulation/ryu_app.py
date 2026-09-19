"""Ryu controller app: installs the reference policy, serves its flow table.

    ryu-manager network_simulation/ryu_app.py

The policy is not written here -- it comes from `firewall_rules.POLICY`, so
the entries this installs and the entries module 6 reads are the same list.
That is the whole point: a firewall verifier comparing detections against a
*different* policy than the one in force reports drift as if it were
coverage failure.

To hand module 6 the resulting table, run ryu-manager with the REST API and
save what it returns:

    ryu-manager --observe-links ryu.app.ofctl_rest network_simulation/ryu_app.py
    curl -s http://localhost:8080/stats/flow/1 > /tmp/flows.json
    python -m source.firewall_check.ryu_log_compare --rules /tmp/flows.json

Or skip the controller entirely and export the same JSON directly, which is
what the tests do:

    python -m network_simulation.firewall_rules --format ryu --output /tmp/flows.json

Ryu is not installed in this project's environment and this file has not
been run here -- see the README for why and what that means.
"""

from __future__ import annotations

from network_simulation.firewall_rules import DEFAULT_ACTION, POLICY, TCP

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
except ImportError as exc:  # pragma: no cover - exercised only with ryu installed
    raise SystemExit(
        "Ryu is not installed (or is incompatible with this Python).\n"
        "    pip install ryu        # needs Python <= 3.9; see network_simulation/README.md\n"
        "The policy itself is importable without Ryu:\n"
        "    python -m network_simulation.firewall_rules --format ryu"
    ) from exc


class ReferenceFirewall(app_manager.RyuApp):
    """A learning switch with the reference policy installed above it."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        for rule in POLICY:
            match = self._match_for(parser, rule)
            # An empty action list is the drop: OpenFlow has no DROP action.
            actions = [] if rule.action == "drop" else [
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]
            self._add_flow(datapath, rule.priority, match, actions)
            self.logger.info("installed %-24s prio=%-4d %s", rule.name, rule.priority, rule.action)

        # Table-miss. With DEFAULT_ACTION == "allow" this punts to the
        # controller so the learning switch can forward it; with "drop" the
        # empty action list makes the network default-deny. Module 6 must be
        # told which, via --default-action.
        miss_actions = [] if DEFAULT_ACTION == "drop" else [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self._add_flow(datapath, 0, parser.OFPMatch(), miss_actions)
        self.logger.info("table-miss installed: default action is %s", DEFAULT_ACTION)

    @staticmethod
    def _match_for(parser, rule):
        kwargs: dict[str, object] = {}
        if rule.protocol is not None:
            kwargs["eth_type"] = 0x0800   # OpenFlow requires eth_type before ip_proto
            kwargs["ip_proto"] = rule.protocol
        if rule.src_net:
            kwargs["ipv4_src"] = rule.src_net
        if rule.dst_net:
            kwargs["ipv4_dst"] = rule.dst_net
        if rule.dst_port is not None:
            kwargs["tcp_dst" if rule.protocol == TCP else "udp_dst"] = rule.dst_port
        return parser.OFPMatch(**kwargs)

    @staticmethod
    def _add_flow(datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=instructions))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        """Plain L2 learning for whatever the policy let through. Nothing
        here blocks anything -- the policy above decides, and this only
        moves permitted frames along."""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        ))
