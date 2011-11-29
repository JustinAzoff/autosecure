import requests
from pyquery import PyQuery as pq

from autosecure.util import re_extract

class Facebook:
    name = "Facebook"
    site = "www.facebook.com"
    settings_url = "https://www.facebook.com/settings?tab=security&section=browsing&t"
    url = "https:/www.facebook.com/ajax/settings/security/browsing.php"
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

        print 'sending payload', payload
        r = requests.post(self.url, data=payload, headers=session)
        print r
