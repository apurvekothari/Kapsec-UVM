import json
from datetime import datetime, date
import requests

api_key = "50e9d143508ec3afaa09b0fd95be66cedc3f8a54"

usr = "priyanka"
pwd = "Test@123"


def get_auth(user=usr, password=pwd):
    response = requests.post("http://kapsec.kapstonellc.co:8080/api/v2/api-token-auth/",
    json={"username": user, "password": password})
    if response.status_code == 200:
        data = response.json()
        api_key = data.get("token")
    return api_key


def get_engagement(api_key):
    response = requests.get("http://kapsec.kapstonellc.co:8080/api/v2/engagements/",
    headers={"Authorization": f"Token {api_key}"})
    if response.status_code == 200:
        data = response.json()
    return data


def import_scan(api_key, file, engagement_id, scan_type, tags=[], severity="Info", active=True, verified=True):
    today = str(date.today())
    response = requests.post("http://kapsec.kapstonellc.co:8080/api/v2/import-scan/",
    data={

            })



import requests

url = "http://kapsec.kapstonellc.co:8080/api/v2/import-scan/"

payload = {'scan_type': '<string>',
'engagement': '<integer>',
'scan_date': '2020-09-17',
'minimum_severity': 'Info',
'active': 'true',
'verified': 'true',
'endpoint_to_add': '<integer>',
'test_type': '<string>',
'file': '<binary>',
'lead': '<integer>',
'tags': '["<string>","<string>"]',
'close_old_findings': 'false',
'push_to_jira': 'false'}
files = [

]
headers = {
'Content-Type': 'multipart/form-data'
}

response = requests.request("POST", url, headers=headers, data = payload, files = files)

print(response.text.encode('utf8'))
