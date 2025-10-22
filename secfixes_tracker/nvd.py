import requests
import datetime
import urllib.parse
import requests


class API:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

    def __init__(self, api_key=None):
        # Try to get API key from environment variable if not provided
        if api_key is None:
            import os
            api_key = os.environ.get('NVD_API_KEY')
        self.api_token = api_key

    def cves(
        self,
        *,
        last_mod_start_date: datetime.datetime = None,
        last_mod_end_date: datetime.datetime = None,
        pub_start_date: datetime.datetime = None,
        pub_end_date: datetime.datetime = None,
        start_index: int = 0,
    ):
        if (last_mod_start_date is None) ^ (last_mod_end_date is None):
            raise ValueError(
                "last_mod_start_date and last_mod_end_date must both be provided at the same time"
            )
        
        if (pub_start_date is None) ^ (pub_end_date is None):
            raise ValueError(
                "pub_start_date and pub_end_date must both be provided at the same time"
            )

        params = {
            "startIndex": start_index,
        }

        if not last_mod_start_date is None:
            params["lastModStartDate"] = last_mod_start_date.isoformat()

        if not last_mod_end_date is None:
            params["lastModEndDate"] = last_mod_end_date.isoformat()
            
        if not pub_start_date is None:
            params["pubStartDate"] = pub_start_date.isoformat()

        if not pub_end_date is None:
            params["pubEndDate"] = pub_end_date.isoformat()

        url = "{}?{}".format(self.url, urllib.parse.urlencode(params))
        print(url)

        headers = {}
        if not self.api_token is None:
            headers["apiKey"] = self.api_token

        # Add headers for API compliance
        headers["User-Agent"] = "secfixes-tracker/1.0"
        
        # With API key, rate limits are much higher, so simple request is sufficient
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
