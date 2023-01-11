import argparse
import base64
import time
from pprint import pprint
import requests
from functools import wraps
import pickle
from os.path import exists

cache = {}

def Cache(function):

    def wrraper(*args, **kwargs):
        global cache

        time_to_live = 60 * 60 * 24 * 7 * 26
        if args[1] not in cache or time.time() - cache[args[1]][1] > time_to_live:
            cache[args[1]] = (function(*args, **kwargs), time.time())
            return cache[args[1]][0]
        else:
            return cache[args[1]][0]
    return wrraper

class VTClient():

    def __init__(self, key, maximum_age: int):
        self.vskey = key
        self.max_age = maximum_age

    def submit_scan(self, url: str):
        api_endpoint = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-apikey": self.vskey
        }
        return requests.post(api_endpoint, data=f'url={url}', headers=headers)

    def get_analysis_by_id(self, id: str):
        headers = {"accept": "application/json",
                   "x-apikey": self.vskey}
        api_endpoint = f"https://www.virustotal.com/api/v3/analyses/{id}"

        response = requests.get(api_endpoint, headers=headers)
        j_response = response.json()

        if response.status_code == 200:
            while j_response['data']['attributes']['status'] != 'completed':
                time.sleep(1)
                response = requests.get(api_endpoint, data=f'url={url}', headers=headers)
                j_response = response.json()

        return response

    def get_analysis(self, url: str, encode: bool = True):
        if encode:
            url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url}"
        headers = {"accept": "application/json",
                   "x-apikey": self.vskey}
        response = requests.get(api_endpoint, headers=headers)

        # If not found
        """
        {'error': {'message': 'URL "aHR0cHM6Ly93d3cuMTIzMTIzMTI0MTI0MTI0dTFpdWZoMWkzdWZuMjNmbmVqZm5za2RqZm5rc2RqZm5rc2RmZHNhZnNkZi5jb20" not found', 'code': 'NotFoundError'}}"""
        return response

    @Cache
    def scan_url(self, url: str):
        print('I DIDNT COME FROM CACHE')
        response = self.get_analysis(url)
        if response.status_code == 400 and response.json()['error']['code'] == 'NotFoundError':
            submit_resp = self.submit_scan(url)
            analysis_id = submit_resp.json()['data']['id']
            return self.get_analysis_by_id(analysis_id)

        elif self.parse_response(response)['need_analysis']:
            submit_resp = self.submit_scan(url)
            analysis_id = submit_resp.json()['data']['id']
            return self.get_analysis_by_id(analysis_id)
        else:
            return response

    def parse_response(self, response: requests.Response):
        if response.status_code != 200:
            return None

        r = response.json()
        attr = r['data']['attributes']
        response_type = r['data']['type']

        if response_type == 'url':
            return {
                'url': attr['url'],
                'last_analysis_date': attr['last_analysis_date'],
                'need_analysis': time.time() - attr['last_analysis_date'] > self.max_age,
                'results': attr['last_analysis_stats']  # harmless, malicious, suspicious, undetected
            }
        elif response_type == 'analysis':
            return {
                'last_analysis_date': time.time(),
                'need_analysis': False,
                'results': attr['stats']  # harmless, malicious, suspicious, undetected
            }

def main():
    key = "09e7421d1cf56d8eb7b5d236d68cce0336e1fd29d21791014c2dc75ec62237a1"
    max_age = 60 * 60 * 24 * 7 * 26

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan", action="store_true")
    parser.add_argument("-a", "--api_key")
    parser.add_argument("urls")
    parser.add_argument("-m", "--max_age", )
    parser.add_argument("-c", "--cache_data", action="store_true")
    args = parser.parse_args()

    if args.cache_data:
        pprint(cache)
        return

    if args.api_key:
        key = args.api_key

    if args.max_age:
        max_age = args.max_age * 60 * 60 * 24 * 7 * 4

    sha = VTClient(key, max_age)

    if args.scan:
        for url in args.urls.split(","):
            submit_resp = sha.submit_scan(url)
            analysis_id = submit_resp.json()['data']['id']
            analysis = sha.get_analysis_by_id(analysis_id)
            pprint(sha.parse_response(analysis))
        return

    if args.urls:
        url_list = args.urls.split(',')
        for url in url_list:
            analysis = sha.scan_url(url)
            pprint(sha.parse_response(analysis))


if __name__ == '__main__':
    if exists(".pickled_cache"):
        with open(".pickled_cache", "rb") as f:
            cache = pickle.load(f)
    else:
        cache = {}

    main()

    with open(".pickled_cache", "wb") as f:
        pickle.dump(cache, f)
    # j = VTClient(key).get_analysis("https://walla.com").json()
