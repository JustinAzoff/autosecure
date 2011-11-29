from facebook import Facebook
from twitter import Twitter


all_handlers = [
    Facebook,
    Twitter,
]

handler_map = {}
for h in all_handlers:
    handler_map[h.site] = h
