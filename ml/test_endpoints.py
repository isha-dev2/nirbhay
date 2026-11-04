import requests

for lang in ["en", "hi", "gu"]:
    url = f"https://cybercrime.gov.in/assets/i18n/{lang}.json"
    try:
        r = requests.get(url, headers={"User-Agent": "Nirbhay-ScamResearch/1.0"}, timeout=10)
        print(f"{url} -> status {r.status_code}, length {len(r.text)}")
        if r.status_code == 200:
            print("Preview:", r.text[:200])
    except Exception as e:
        print(f"{url} -> error {e}")


