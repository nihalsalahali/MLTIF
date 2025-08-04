#!/usr/bin/env python3
"""
FLARE LSMA Controller for Ryu
==============================
- Receives alerts (validated JSON)
- Applies mitigation policy: push flow_mod to switch
- REST API server using WSGI (Ryu's built-in REST framework)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

import json
import logging

# REST API base URL
FLARE_BASE_URL = '/flare'
FLARE_ALERT_URL = '/flare/alert'


class LSMAController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(LSMAController, self).__init__(*args, **kwargs)
        self.logger.info("✅ FLARE LSMA Controller for Ryu starting...")
        wsgi = kwargs['wsgi']
        wsgi.register(LSMAAlertController, { 'lsma_app': self })
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install default table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                 priority=priority,
                                 match=match,
                                 instructions=inst,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def install_mitigation_flow(self, src_ip, dst_ip):
        self.logger.info("🚨 Installing mitigation flow: src=%s dst=%s", src_ip, dst_ip)

        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = []  # No actions = drop
            self.add_flow(dp, priority=50000, match=match, actions=actions,
                          idle_timeout=600, hard_timeout=0)


class LSMAAlertController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(LSMAAlertController, self).__init__(req, link, data, **config)
        self.lsma_app = data['lsma_app']

    @route('flare', FLARE_ALERT_URL, methods=['POST'])
    def receive_alert(self, req, **kwargs):
        try:
            alert = req.json if req.body else {}
            alert_id = alert['alert_id']
            confidence = alert['classifier_confidence']
            frag = alert['flags']['FRAG']
            rst = alert['flags']['RST']

            self.lsma_app.logger.info("✅ Received alert: %s", alert_id)

            # Example logic: if risky → install drop flow
            if confidence > 0.9 or frag or rst:
                src_ip = alert['source_ip']
                dst_ip = alert['destination_ip']
                self.lsma_app.install_mitigation_flow(src_ip, dst_ip)

            body = json.dumps({ "result": "processed", "alert_id": alert_id })
            return Response(content_type='application/json', body=body)

        except Exception as e:
            self.lsma_app.logger.error("Error processing alert: %s", str(e))
            return Response(status=400, body="Invalid alert JSON")
