#!/usr/bin/python

import requests
import json
import urllib3
import xml.etree.ElementTree as ET
from tabulate import tabulate
import sys
import socket
import urllib

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

    params = (
        ('username', username),
        ('password', password),
    )
    url = base_url+"/sso/v1/tickets"
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

    params = (
        ('service', 'https://'+server_ip+':30603/app-dashboard'),
    )
    ticket=get_ticket()
    url = base_url+"/sso/v1/tickets/"+ticket
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
    auth_headers=get_auth_headers()
    payload = "{\"limit\": 100,\"next_from\": \"0\",\"filter\": {}}"
    response = requests.post(url, headers=auth_headers, data=payload, verify=False)
    unformatted = response.text
    return json.loads(unformatted)

######################################
# Following function performs POST
# request on CW API
######################################

def run_get(url):
    auth_headers=get_auth_headers()
    try:
        response = requests.get(url, headers=auth_headers, verify=False)
        
        if response.status_code in [200, 201]:
            return response.text
        print("\n\nStatus Code: ", response.status_code, "\n")
#        print(response.text) should be parsed. It wont print as is
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

def print_node_name():
    url = base_url+"/crosswork/inventory/v1/nodes/query"
    parsed=run_post(url)
    for index in parsed["data"]:
        print( index["host_name"])

def getNodes(server_ip, user, pwd):
#    url = 'https://'+server_ip+':30603/restconf/data/v1/cisco-resource-physical:node?.depth=1'
    url = base_url+'/restconf/data/v1/cisco-resource-physical:node?.depth=1'
    node_list = []
    nodes = run_get(url)
    root = ET.fromstring(nodes)
    lastIndex = int(root[0][1].text)
    if lastIndex >= 0:
        for node in root[1]:
            try:
                node_name = node.find('{urn:cisco:params:xml:ns:yang:resource:device}name').text
            except:
                node_name = "NA"
            try:
                node_product_type = node.find('{urn:cisco:params:xml:ns:yang:resource:device}product-type').text
            except:
                node_product_type = "NA"
            try:
                sw_version = node.find('{urn:cisco:params:xml:ns:yang:resource:device}software-version').text
            except:
                sw_version = "NA"
            try:
                node_communication_state = node.find('{urn:cisco:params:xml:ns:yang:resource:device}communication-state').text
            except:
                node_communication_state = "NA"
            node_list.append([node_name, node_product_type, sw_version, node_communication_state])
        print(tabulate(sorted(node_list), headers=(['Device Name', 'Product Type', 'SW Version', 'Communication State'])))

    else:
        print("No nodes found")

################################
#           MAIN
################################

if __name__ == "__main__":
    if len(sys.argv)!=4:
       print('\nMust pass CNC IP, CNC Username and CNC User Password\n')
       exit()
    scripts, server_ip, username, password = sys.argv

# Decode to non-ASCI

    password = urllib.parse.unquote(password)

    if not isOpen(server_ip, 30603):
        print("\nERROR: " + server_ip + " is not reachable, either the server is down or port 30603 is filtered\n")
        exit()

    base_url = "https://" + server_ip + ":30603"
    getNodes(server_ip, username, password)
