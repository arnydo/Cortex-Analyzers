import requests
import json


class UrlscanException(Exception):
    pass


class Urlscan:
    def __init__(self, query=""):
        assert len(query) > 0, "Query must be defined"
        self.query = query

    def search(self):
        payload = {"q": self.query}
        r = requests.get("https://urlscan.io/api/v1/search/", params=payload)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)

    def scan(self, api_key):
        headers = {
            'Content-Type': 'application/json',
            'API-Key': api_key,
        }
        data = '{"url": %s, "public": "on"}' % self.query
        r = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=data, verify=False)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns {0} and data was {1}".format(r.status_code, data))
