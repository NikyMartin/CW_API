#!/usr/bin/python

# April 12 2023
# First Release

# May 6 2024
# Added control on TP list len = 1
# Added paging

import requests
import json
import urllib3
from tabulate import tabulate
import sys
import xml.etree.ElementTree as ET
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

######################################
# Following function returns CW ticket
######################################

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
    url = base_url + "/crosswork/sso/v1/tickets/"+ticket
    response = requests.post(url, headers=headers, params=params, verify=False)
#  If get ticket is ok, no further needs for checking token
    return response.text

######################################
# Following function deletes CW Ticket
######################################

def delete_ticket():
    print("\nExecuting delete Ticket")
    url = base_url + "/crosswork/sso/v1/tickets/"+ticket
    auth_headers = {
        'Content-Type': 'application/json',
        'Authorization': token,
    }
    try:
        response = requests.delete(url, headers=auth_headers, verify=False)
        print("Status Code: ", response.status_code)
    except Exception as e:
        print(str(e))
        print("Cannot run DELETE "+url)
        exit()

    exit()

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
        time.sleep(0.01)
        response = requests.get(url, headers=auth_headers, verify=False)
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            return response.text
#        print(response.text) should be parsed. It wont print as is
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

def parseTP(TP, TP_list):
    try:
        TP_name = TP["tp.discovered-name"]
    except:
        TP_name = "NA"
    try:
        TP_type = TP["tp.type"]
    except:
        TP_type = "NA"
    try:
        TP_layer_rate = TP["tp.layer-rate"]
    except:
        TP_layer_rate = "NA"
    try:
        TP_oper_state = TP["tp.oper-state"]
        if TP_oper_state == "com:oper-state-up":
            TP_oper_state = "UP"
        if TP_oper_state == "com:oper-state-down":
            TP_oper_state = "DOWN"
        if TP_oper_state not in ["UP", "DOWN"]:
            TP_oper_state = "?"
    except:
        TP_oper_state = "NA"
    try:
        IP = ""
        IP_list = TP["tp.ip-tp"]["tp.ip-address"]
        for child in IP_list:
            IP = IP + " " + child
    except:
        IP = "NA"

    TP_list.append([TP_name, TP_type, IP, TP_oper_state, TP_layer_rate])

    return (TP_list)

def getNodeTP(node_name):
    TP_list = []
    index = 0
    lastIndex = 99

    while lastIndex == 99:

        url = base_url + "/restconf/data/v1/cisco-resource-ems:termination-point?ndFdn=MD=CISCO_EPNM!ND=" + node_name
        url = url + "&.startIndex=" + str(index)
        api_output = json.loads(run_get(url, 'json'))
        lastIndex = api_output["com.response-message"]["com.header"]["com.lastIndex"]

        print("Last Index =", lastIndex)

        if lastIndex == -1:
            print("TP List not found")
            break

        if lastIndex == 0 or lastIndex % 100 == 0:
            TPs = api_output["com.response-message"]["com.data"]["tp.termination-point"]
            TP_list = parseTP(TPs, TP_list)
            break

        TPs = api_output["com.response-message"]["com.data"]["tp.termination-point"]
        for TP in TPs:
            TP_list = parseTP(TP, TP_list)

        index = index + 100

    print("\nNode " + node_name + " has " + str(lastIndex + 1) + " Termination Points\n")
    print(tabulate(sorted(TP_list), headers=(['TP Name', 'TP Type', 'IP', 'Oper State', 'Layer Rate'])))


def timeStamp():
    current_time = now.strftime("%H:%M:%S")
    print("\nServer Time =", current_time)

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

    if not isNode(node_name):
        print("Node",node_name,"not found")
        exit(1)
    print("Node",node_name,"found")
    getNodeTP(node_name)

    delete_ticket()