import re
def re_extract(rex, data):
    m = re.search(rex, data)
    if m:
        return m.groups()[0]
