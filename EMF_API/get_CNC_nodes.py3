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
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            unformatted = response.text
            return json.loads(unformatted)
        print("Could not execute POST " + url)
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run POST "+url)
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

######################################
# Following function returns UUID for
# input_node
######################################

def getNodesDLM():
    url = base_url + "/crosswork/inventory/v1/nodes/query"
    node_list = []
    parsed = run_post(url)
    try:
        nodes = parsed["data"]
        print("\nFound", len(nodes), "nodes\n")
    except:
        print("No nodes found")
        exit(1)
    for node in nodes:
        try:
            node_name = node["host_name"]
        except:
            node_name = "NA"
        try:
            ip_address = node["node_ip"]["inet_addr"]
        except:
            ip_address = "NA"
        try:
            product_type = node["product_info"]["product_type"]
        except:
            product_type = "NA"
        try:
            software_version = node["product_info"]["software_version"]
        except:
            software_version = "NA"
        try:
            capability_list = ""
            capabilities = node["product_info"]["capability"]
            for capability in capabilities:
                capability_list = capability_list + " " + capability
        except:
            capability_list = "NA"

        node_list.append([node_name, ip_address, product_type, software_version, capability_list])
    print(tabulate(sorted(node_list), headers=(['Device Name', 'IP Address', 'Product Type', 'SW Version',
                                                'Capabilities'])))

def getNodesEMS(server_ip, user, pwd):
#    url = 'https://'+server_ip+':30603/restconf/data/v1/cisco-resource-physical:node?.depth=1'
    url = base_url+'/restconf/data/v1/cisco-resource-physical:node?.depth=1'
    node_list = []
    nodes = run_get(url,'xml')
    try:
        root = ET.fromstring(nodes)
    except:
        print("Could not extract XML form reply. Exiting")
        exit(1)
    lastIndex = int(root[0][1].text)
    if lastIndex >= 0:
        print("\nFound", len(root[1]), "nodes\n")
        for node in root[1]:
            try:
                node_name = node.find('{urn:cisco:params:xml:ns:yang:resource:device}name').text
            except:
                node_name = "NA"
            try:
                ip_address = node.find('{urn:cisco:params:xml:ns:yang:resource:device}management-address').text
            except:
                ip_address = "NA"
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
            try:
                lifecycle_state = node.find('{urn:cisco:params:xml:ns:yang:resource:device}lifecycle-state').text
            except:
                lifecycle_state = "NA"
            try:
                collection_status = node.find('{urn:cisco:params:xml:ns:yang:resource:device}collection-status').text
            except:
                collection_status = "NA"

            node_list.append([node_name, ip_address, node_product_type, sw_version, node_communication_state,
                              lifecycle_state])
        print(tabulate(sorted(node_list), headers=(['Device Name', 'IP Address', 'Product Type', 'SW Version',
                                                    'Communication State', 'Lifecycle State'])))

    else:
        print("No nodes found")


def timeStamp():
    current_time = now.strftime("%H:%M:%S")
    print("\nServer Time =", current_time)

################################
#           MAIN
################################

if __name__ == "__main__":
    if len(sys.argv)!=5:
       print('\nMust pass CNC IP, CNC User Name, CNC User Password and API Type\n')
       exit()
    scripts, server_ip, username, password, API = sys.argv

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

    if API == "DLM_API":
        getNodesDLM()
        exit()
    if API == "EMS_API":
        getNodesEMS(server_ip, username, password)
        exit()

    print("No API (must be DLM_API or EMF_API)??")
