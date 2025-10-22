import requests
import datetime
import urllib.parse
import requests


class API:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

    def __init__(self, api_key=None):
        self.api_token = api_key

    def cves(
        self,
        *,
        last_mod_start_date: datetime.datetime = None,
        last_mod_end_date: datetime.datetime = None,
        start_index: int = 0,
    ):
        if (last_mod_start_date is None) ^ (last_mod_end_date is None):
            raise ValueError(
                "last_mod_start_date and last_mod_end_date must both be provided at the same time"
            )

        params = {
            "startIndex": start_index,
        }

        if not last_mod_start_date is None:
            params["lastModStartDate"] = last_mod_start_date.isoformat()

        if not last_mod_end_date is None:
            params["lastModEndDate"] = last_mod_end_date.isoformat()

        url = "{}?{}".format(self.url, urllib.parse.urlencode(params))
        print(url)

        headers = {}
        if not self.api_token is None:
            headers["apiKey"] = self.api_key

        # Add rate limiting headers to be respectful to NVD API
        headers["User-Agent"] = "secfixes-tracker/1.0"
        
        # Retry logic for rate limiting
        import time
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, headers=headers, timeout=30)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:  # Rate limited
                    if attempt < max_retries - 1:
                        print(f"W: Rate limited, waiting {retry_delay} seconds before retry {attempt + 1}/{max_retries}")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                raise
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    print(f"W: Request failed, retrying in {retry_delay} seconds: {e}")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                raise
