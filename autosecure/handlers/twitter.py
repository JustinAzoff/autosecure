import requests
from pyquery import PyQuery as pq

from autosecure.util import re_extract

class Twitter:
    name = "Twitter"
    site = "twitter.com"
    settings_url = "http://twitter.com/settings/account"
    url = "http://twitter.com/settings/accounts/update"
    payload = {"user[ssl_only]": "1",
               "_method":        "put",
              }

    def extract_user(self, session):
        return re_extract("twid=u%3D([\d]+)%", session['Cookie'])

    def secure(self, session):
        payload = self.payload.copy()
        session['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        session['Accept-Language'] = 'en-US,en;q=0.8'
        session['Accept-Charset'] = 'ISO-8859-1,utf-8;q=0.7,*;q=0.3'
        settings_page = requests.get(self.settings_url, headers=session).content
        print settings_page
        q=pq(settings_page)

        #TODO: refacter
        post_form_id = q("[name=authenticity_token]")[0].value
        payload["authenticity_token"] = authenticity_token

        print 'sending payload', payload
        r = requests.post(self.url, data=payload, headers=session)
