Autosecure
==========
sniff session cookies like firesheep, and then automatically secure users
accounts.

Initially based off of https://github.com/jonty/idiocy almost everything rewritten.


Requires
--------
* Python + pynids,requests, pyquery

Running
-------

* apt-get install python-nids python-pyquery
* pip install requests

or to get everything via pip:

* pip install .

then

* iw wlan0 interface add mon0 type monitor && ifconfig mon0 up
* ./run -i mon0

or if you installed it using pip,

* autosecure -i mon0
