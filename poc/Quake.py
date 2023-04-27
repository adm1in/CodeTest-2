import requests

token = 'c46ff334-45c6-489f-822f-152deba67a65'

class Quake():
    def __init__(self, token=None):
        self.headers = {'User-Agent': 'curl/7.80.0', 'Content-Type': 'application/json'}
        self.credits = 0
        self.token = token
        self.check_token()

    def token_is_available(self):
        if self.token:
            try:
                self.headers['X-QuakeToken'] = self.token
                resp = requests.get(
                    'https://quake.360.cn/api/v3/user/info', headers=self.headers)

                if 'month_remaining_credit' not in resp.text:
                    print(resp.text)

                if resp and resp.status_code == 200 and resp.json()['code'] == 0:
                    return True
            except Exception as ex:
                print(str(ex))
        return False

    def check_token(self):
        if self.token_is_available():
            return True
        else:
            print("The Quake api token is incorrect. "
                            "Please enter the correct api token.")

    def search(self, dork, pages=2):
        search_result = set()
        data = {"query": dork, "size": 10,
                "ignore_cache": "false", "start": 1}
        try:
            for page in range(1, pages + 1):
                data['start'] = page
                url = "https://quake.360.cn/api/v3/search/quake_service"
                resp = requests.post(
                    url, json=data, headers=self.headers, timeout=80)
                if resp and resp.status_code == 200 and resp.json()['code'] == 0:
                    content = resp.json()
                    for match in content['data']:
                        search_result.add("%s:%s" %
                                          (match['ip'], match['port']))
                else:
                    print("[PLUGIN] Quake:{}".format(resp.text))
        except Exception as ex:
            print(str(ex))
        return search_result

def check(**kwargs):
    qk = Quake(token=token)
    z = qk.search(kwargs['url'])
    for url in z:
        print(url)
    
if __name__ == "__main__":
    qk = Quake(token=token)
    z = qk.search('app:"F5_BIG-IP"')
    print(z)