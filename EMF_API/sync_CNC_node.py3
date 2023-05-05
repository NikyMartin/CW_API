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
    url = base_url + "/crosswork/sso/v1/tickets"
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
    url = base_url + "/crosswork/sso/v1/tickets/"+ticket
    response = requests.post(url, headers=headers, params=params, verify=False)
    return response.text

######################################
# Following function performs PUT
# request on CW API
######################################

def run_put(url,payload):
    print("Executing PUT", url)
    auth_headers = {
        'accept': 'application/json',
        'Authorization': token,
    }
    try:
        response = requests.put(url, headers=auth_headers, data=payload, verify=False)
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            return response.text
        print("Could not execute PUT " + url)
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run PUT "+url)
        exit(1)

######################################
# Following function performs GET
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
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            return response.text
        print("Could not execute GET "+url)
        print("\nIf Status Code is 404, it can be common inventory cAPP is not installed\n")
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run GET "+url)
        exit(1)

    return response.text

def isNode(node_name):
    url = base_url + "/restconf/data/v1/cisco-resource-physical:node?name=" + node_name
    node = run_get(url, 'xml')
    root = ET.fromstring(node)
    lastIndex = int(root[0][1].text)
    if lastIndex >= 0:
        return True

    else:
        return False

def getNodeID(node_name):
    url = base_url + '/crosswork/inventoryRestServiceSub/ifm/inventory-rest/devices'
    found = False
    node_id = ""
    nodes = json.loads(run_get(url,'json'))
    if len(nodes) == 0:
        print("Node output is an empty list. Exiting")
        exit(1)

    for node in nodes:
        try:
            nodeName = node["deviceName"]
        except:
            nodeName = "NA"
        if nodeName == node_name:
            try:
                node_id = node["entityId"]
                found = True
            except:
                print("Could not extract node ID for node", node_name, "Exiting")
                exit(1)
            break

    return found, node_id

def syncNode(nodeId):
    url = base_url + '/crosswork/inventoryRestServiceSub/ifm/inventory-rest/syncDevice'
    payload = json.dumps({
        "deviceIds": nodeId
    })
    result = run_put(url,payload)

    if result == "Success":
        print("\nSyncing node", node_name)
    else:
        print("\nGot", result)

def timeStamp():
    current_time = now.strftime("%H:%M:%S")
    print("\nServer Time =", current_time)

################################
#           MAIN
################################

if __name__ == "__main__":
    if len(sys.argv)!=5:
       print('\nMust pass CNC IP, CNC User Name, CNC User Password and Node Name\n')
       exit()
    scripts, server_ip, username, password, node_name = sys.argv

# Decode password from HTML to non-ASCI

    password = urllib.parse.unquote(password)

    timeStamp()
    print("\nChecking Server Port")

    if not isOpen(server_ip, 30603):
        print("\nERROR: " + server_ip + " is not reachable, either the server is down or port 30603 is filtered\n")
        exit()

    base_url = "https://" + server_ip + ":30603"
    ticket = get_ticket()
    token = get_token()

    if not isNode(node_name):
        print("Node",node_name,"not found. Exiting")
        exit(1)
    print("Node",node_name,"found")

    found, nodeId = getNodeID(node_name)

    if not found:
        print("Could not find Node ID for node", node_name, "Exiting")
        exit(1)

    print("Node ID for node", node_name, "is", nodeId)

    syncNode(nodeId)
