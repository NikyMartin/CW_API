#!/usr/bin/python

import requests
import json
import urllib3
import xml.etree.ElementTree as ET
from tabulate import tabulate
import sys
import socket
import urllib
from datetime import datetime

now = datetime.now()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'Accept': 'text/plain',
    'Cache-Control': 'no-cache',
    'Content-Type': 'application/x-www-form-urlencoded',
}

######################################
# Following function returns CW ticket
######################################

def printAllResponse(response):
    print("Status Code: ",response.status_code)
    print("Headers: ",response.headers)
    print("Url: ",response.url)
    print("History: ",response.history)
    print("Encoding: ",response.encoding)
    print("Reason: ",response.reason)
    print("Cookies: ",response.cookies)
    print("Elapsed: ",response.elapsed)
    print("Request: ",response.request)
    print("Content: ",response._content)

def isOpen(server_ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((server_ip, int(port)))
      s.shutdown(2)
      return True
   except:
      return False

def get_ticket():
    print("Executing GET Tiket")
    params = (
        ('username', username),
        ('password', password),
    )
    url = base_url+"/crosswork/sso/v1/tickets"
    response = requests.post(url, headers=headers, params=params, verify=False)
    if response.status_code in [200,201]:
        return response.text
    else:
        print("Status Code: ", response.status_code)
        print("Could not execute POST " + url)
        print(response.text)
        exit()

######################################
# Following function returns CW JWT
######################################

def get_token():
    print("Executing GET Token")
    params = (
        ('service', 'https://'+server_ip+':30603/app-dashboard'),
    )
    ticket=get_ticket()
    url = base_url+"/crosswork/sso/v1/tickets/"+ticket
    response = requests.post(url, headers=headers, params=params, verify=False)
    return response.text


######################################
# Following function authenticated
# headers using JWT
######################################

def get_auth_headers():

    token=get_token()
    headers = {
       'accept': 'application/json',
       'Authorization': token,
    }
    return headers

######################################
# Following function performs POST
# request on CW API
######################################

def run_post(url):
    print("Executing POST", url)
    auth_headers = {
        'accept': 'application/json',
        'Authorization': token,
    }
    payload = "{\"limit\": 100,\"next_from\": \"0\",\"filter\": {}}"
    try:
        response = requests.post(url, headers=auth_headers, data=payload, verify=False)
        if 200 <= response.status_code <= 210:
            print("Status Code", response.status_code)
            unformatted = response.text
            return json.loads(unformatted)
        print("\n\nStatus Code: ", response.status_code, "\n")
        print("Could not execute GET " + url)
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run GET "+url)
        exit(1)

######################################
# Following function performs POST
# request on CW API
######################################


def run_get(url,encoding):
    print("Executing GET", url)
    auth_headers = {
        'accept': 'application/' + encoding,
        'Authorization': token,
    }
    try:
        response = requests.get(url, headers=auth_headers, verify=False)
        
        if 200 <= response.status_code <= 210:
            print("Status Code", response.status_code)
            return response.text
        print("\nStatus Code: ", response.status_code, "\n")
        print("Could not execute GET "+url)
        print("\nIf Status Code is 404, it can be common inventory cAPP is not installed\n")
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run GET "+url)
        exit(1)

    return response.text

######################################
# Following function returns UUID for
# input_node
######################################

def getNodeIDs():
    url = base_url+'/crosswork/inventoryRestServiceSub/ifm/inventory-rest/devices'
    node_list = []
    nodes = json.loads(run_get(url,'json'))
    if len(nodes) == 0:
        print("Node output is an empty list. Exiting")
        exit(1)
    print("\nFound", len(nodes), "nodes\n")

    for node in nodes:
        try:
            node_name = node["deviceName"]
        except:
            node_name = "NA"
        try:
            node_id = node["entityId"]
        except:
            node_id = "NA"

        node_list.append([node_name, node_id])
    print(tabulate(sorted(node_list), headers=(['Device Name', 'Node ID'])))

################################
#           MAIN
################################

if __name__ == "__main__":
    if len(sys.argv)!=4:
       print('\nMust pass CNC IP, CNC User Name and CNC User Password\n')
       exit()
    scripts, server_ip, username, password = sys.argv

# Decode password from HTML to non-ASCI

    password = urllib.parse.unquote(password)

    print("\nExecution Started !!!")
    print("\nChecking Server Port")

    if not isOpen(server_ip, 30603):
        print("\nERROR: " + server_ip + " is not reachable, either the server is down or port 30603 is filtered\n")
        exit()

    base_url = "https://" + server_ip + ":30603"
    token = get_token()

    getNodeIDs()

    current_time = now.strftime("%H:%M:%S")
    print("\nTime =", current_time, "\n")