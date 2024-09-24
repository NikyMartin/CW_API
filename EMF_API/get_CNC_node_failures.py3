#!/usr/bin/python

import requests
import json
import urllib3
import xml.etree.ElementTree as ET
from tabulate import tabulate
import sys
import os
import socket
import urllib
import time
import http.client
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
    print("Executing GET Ticket")
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

    url = base_url + "/crosswork/sso/v1/tickets/" + ticket
    response = requests.post(url, headers=headers, params=params, verify=False)
#  If get ticket is ok, no further needs for checking token
    return response.text

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
        time.sleep(0.01)
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

def is_equipment_list(node):
    print("Checking if node has an equipment list")
    try:
        node.find('{urn:cisco:params:xml:ns:yang:resource:device}equipment-list').tag
        return True
    except:
        return False

def timeStamp():
    current_time = now.strftime("%H:%M:%S")
    print("\nServer Time =", current_time)

def getNodeState():
    url = base_url + "/crosswork/inventoryRestServiceSub/ifm/inventory-rest/devices"
    found = False
    nodes = json.loads(run_get(url, 'json'))
    if len(nodes) == 0:
        print("Node output is an empty list. Exiting")
        exit(1)

    for node in nodes:
        try:
            nodeName = node["deviceName"]
        except:
            nodeName = "NA"
        if nodeName == node_name:
            print("Node", node_name, "found")
            try:
                lifecycleState = node["lifeCycleState"]
                collectionStatus = node["inventoryCollectionStatus"]
                print("\nLifecycle Sate:", lifecycleState)
                print("Collection Status:", collectionStatus, "\n")
                found = True

            except:
                print("Could not extract LifeCycle State or Collection Status for node. Exiting")
                exit(1)

            if lifecycleState == "MANAGED_AND_SYNCHRONIZED":
                print("Please use this script for nodes with a different Lifecycle State. Exiting\n")
                exit(1)

            break
    if not found:
        print("Node", node_name, "not found. Exiting")
        exit(1)


def getNodeFailures():
    url = base_url + "/restconf/data/v1/cisco-resource-physical:node?name=" + node_name
    nodes = run_get(url,'xml')
    try:
        root = ET.fromstring(nodes)
    except:
        print("Could not extract XML form reply. Exiting")
        exit(1)
    lastIndex = int(root[0][1].text)
    print("Last Index =", lastIndex)
    if lastIndex >= 0:
        print("Node "+node_name+" found")
        for node in root[1]:
            try:
                lifecycle_state = node.find('{urn:cisco:params:xml:ns:yang:resource:device}lifecycle-state').text
            except:
                print("\nLifecycle State Not Found. Exiting\n")
                exit(1)

            try:
                collection_status = node.find('{urn:cisco:params:xml:ns:yang:resource:device}collection-status').text
            except:
                print("\nCollection Status Not Found. Exiting\n")
                exit(1)

            if "<status>" not in collection_status:
                print("\nCollection Status: ", collection_status, "\n")
                exit()

            try:
                root2 = ET.fromstring(collection_status)
                general_code = root2[0].attrib["code"]
                failed_features_code = root2[1].attrib["code"]
                failure_message = root2[1].attrib["message"]
                failure_node_names = root2[1].attrib["names"]
                retry = root2[1].attrib["retry"]
                print("\nGeneral:", general_code)
                print("Failed Feature:", failed_features_code)
                print("Failure Message:",failure_message)
                print("Failure Name:",failure_node_names)
                print("Retry:",retry,"\n")
            except:
                print("\nCollection Status: ", root2[0].attrib["code"],"\n")
                exit(1)

    else:
        print("Node "+node_name+" not found")

################################
#           MAIN
################################
if __name__ == "__main__":
    if len(sys.argv)!=5:
       print('\nMust pass CNC IP, CNC Username, CNC User Password and Node Name\n')
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

    getNodeState()
    getNodeFailures()
