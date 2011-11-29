import requests
from pyquery import PyQuery as pq

from autosecure.util import re_extract

class Twitter:
    name = "Twitter"
    site = "api.twitter.com"
    settings_url = "http://twitter.com/settings/account"
    url = "http://twitter.com/settings/accounts/update"
    payload = {"user[ssl_only]": "1",
               "_method":        "put",
              }

    def extract_user(self, session):
        return re_extract("twid=u%3D([\d]+)%", session['Cookie'])

    def secure(self, session):
        payload = self.payload.copy()
        headers = session.copy()
        del headers['Host']
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        headers['Accept-Language'] = 'en-US,en;q=0.8'
        headers['Accept-Charset'] = 'ISO-8859-1,utf-8;q=0.7,*;q=0.3'
        settings_page = requests.get(self.settings_url, headers=headers).content
        q=pq(settings_page)

        #TODO: refacter
        authenticity_token = q("[name=authenticity_token]")[0].value
        payload["authenticity_token"] = authenticity_token

        print 'sending payload', payload
        r = requests.post(self.url, data=payload, headers=headers)
        print r
