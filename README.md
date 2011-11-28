Autosecure
==========
sniff session cookies like firesheep, and then automatically secure users
accounts.

Initially based off of https://github.com/jonty/idiocy almost everything rewritten.


Requires
--------
* Python + pcap, dpkt, requests, pyquery

Running
-------

* apt-get install libpcap0.8 python-pypcap python-dpkt python-pyquery
* pip install requests

or something like

* pip install pypcap dpkt pquery requests

then

* iw wlan0 interface add mon0 type monitor && ifconfig mon0 up
* ./autosecure.py -i mon0
