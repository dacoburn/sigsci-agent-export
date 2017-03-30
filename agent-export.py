import sys, requests, os, calendar, json
from datetime import datetime, timedelta
import os
import argparse

parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description='Utility for exporting Agent information from a Signal Sciences Site')


parser.add_argument("-c", type=str, 
                        help="Specify the file with the configuration options")

opts = parser.parse_args()


# Initial setup

if "c" in opts and not(opts.c is None):
    confFile = open(opts.c, "r")

    confJson = json.load(confFile)
else:
    confJson = ""


api_host = 'https://dashboard.signalsciences.net'
if "email" in confJson and not(confJson["email"] is None):
    email = confJson["email"]
else:
    email = os.environ.get('SIGSCI_EMAIL') 

if "password" in confJson and not(confJson["password"] is None):
    password = confJson["password"]
else:
    password = os.environ.get('SIGSCI_PASSWORD') 

if "corp" in confJson and not(confJson["corp"] is None):
    corp_name = confJson["corp"]
else:
    corp_name = os.environ.get('SIGSCI_CORP')

if "siteName" in confJson and not(confJson["siteName"] is None):
    site_name = confJson["siteName"]
else:
    site_name = corp_name = os.environ.get('SIGSCI_SITE_NAME')

showPassword = False

# Calculate UTC timestamps for the previous full hour
# E.g. if now is 9:05 AM UTC, the timestamps will be 8:00 AM and 9:00 AM
until_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
from_time = until_time - timedelta(minutes=60)
until_time = calendar.timegm(until_time.utctimetuple())
from_time = calendar.timegm(from_time.utctimetuple())


#Definition for error handling on the response code

def checkResponse(code, responseText):
    if code == 400:
        print("Bad API Request (ResponseCode: %s)" % (code))
        print("ResponseError: %s" % responseText)
        print('url: %s' % url)
        print('from: %s' % from_time)
        print('until: %s' % until_time)
        print('email: %s' % email)
        if showPassword is True:
            print('password: %s' % password)
        print('Corp: %s' % corp_name)
        print('SiteName: %s' % site_name)
        exit(code)
    elif code == 500:
        print("Caused an Internal Server error (ResponseCode: %s)" % (code))
        print("ResponseError: %s" % responseText)
        print('url: %s' % url)
        print('from: %s' % from_time)
        print('until: %s' % until_time)
        print('email: %s' % email)
        if showPassword is True:
            print('password: %s' % password)
        print('Corp: %s' % corp_name)
        print('SiteName: %s' % site_name)
        exit(code)
    elif code == 401:
        print("Unauthorized, likely bad credentials or site configuration, or lack of permissions (ResponseCode: %s)" % (code))
        print("ResponseError: %s" % responseText)
        print('email: %s' % email)
        if showPassword is True:
            print('password: %s' % password)
        print('Corp: %s' % corp_name)
        print('SiteName: %s' % site_name)
        exit(code)
    elif code >= 400 and code <= 599:
        print("ResponseError: %s" % responseText)
        print('url: %s' % url)
        print('from: %s' % from_time)
        print('until: %s' % until_time)
        print('email: %s' % email)
        if showPassword is True:
            print('password: %s' % password)
        print('Corp: %s' % corp_name)
        print('SiteName: %s' % site_name)
        exit(code)


# Authenticate
auth = requests.post(
    api_host + '/api/v0/auth',
    data = {"email": email, "password": password}
)

authCode = auth.status_code
authError = auth.text

checkResponse(authCode, authError)

parsed_response = auth.json()
token = parsed_response['token']

headers = {
	'Content-type': 'application/json',
	'Authorization': 'Bearer %s' % token
}
url = api_host + ('/api/v0/corps/%s/sites/%s/agents' % (corp_name, site_name))
first = True

importFile = "agent.csv"

if os.path.isfile(importFile):
    try:
        os.remove(importFile)
    except OSError as e: 
        if e.errno != errno.ENOENT: 
            raise


while True:
    file = open(importFile, "w")
    file.write("host.remote_addr, agent.name, host.os, host.architecture, agent.status, agent.last_seen, agent.timezone, \
        agent.version, module.type, module.server, module.version, host.num_cpu, agent.addr, agent.active\n")
    response_raw = requests.get(url, headers=headers)
    responseCode = response_raw.status_code
    responseError = response_raw.text

    checkResponse(responseCode, responseError)


    response = json.loads(response_raw.text)
    
    # print(response['data'])

    for request in response['data']:
        output = json.dumps(request)
        print("%s" % output)
        
        agentCSV = ("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s") % (
                request['host.remote_addr'], request['agent.name'], request['host.os'], request['host.architecture'], \
                request['agent.status'], request['agent.last_seen'], request['agent.timezone'], request['agent.version'], \
                request['module.type'], request['module.server'], request['module.version'], request['host.num_cpu'], \
                request['agent.addr'], request['agent.active']
            )

        file.write("%s\n" % agentCSV)

    if "next" in response:
        next_url = response['next']['uri']
        if next_url == '':
            break
        url = api_host + next_url
    else:
        break

