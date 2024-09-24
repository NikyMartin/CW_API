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
    url = base_url+"/crosswork/sso/v1/tickets"
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

    url = base_url+"/crosswork/sso/v1/tickets/"+ticket
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

def getNodeInventory():
    url = base_url + "/restconf/data/v1/cisco-resource-physical:node?name=" + node_name

    node_list = []
    nodes = run_get(url,'xml')
    try:
        root = ET.fromstring(nodes)
    except:
        print("Could not extract XML form reply. Exiting")
        exit(1)
    lastIndex = int(root[0][1].text)
    print("Last Index =", lastIndex)
    if lastIndex >= 0:
        print("Node "+node_name+" exists")
        for node in root[1]:
            if is_equipment_list(node):
                print("Assigning equipment list")
                try:
                    equipment_list = node.find('{urn:cisco:params:xml:ns:yang:resource:device}equipment-list')
                    print("\nNode " + node_name + " has " + str(len(equipment_list)) + " equipments in the list\n")
                    for equipment in equipment_list:
                        try:
                            equipment_name = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:foundation}name').text
                        except:
                            equipment_name = "NA"
                        try:
                            equipment_type = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:resource:physical}equipment-type').text
                        except:
                            equipment_type = "NA"
                        try:
                            equipment_description = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:foundation}description').text
                        except:
                            equipment_description = "NA"
                        try:
                            product_id = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:resource:physical}product-id').text
                        except:
                            product_id = "NA"
                        try:
                            serial_number = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:resource:physical}serial-number').text
                        except:
                            serial_number = "NA"
                        try:
                            operational_state = equipment.find('{urn:cisco:params:xml:ns:yang:restconf:resource:physical}operational-state-code').text
                        except:
                            operational_state = "NA"
                        if serial_number != "NA" and 'IDPROM' not in equipment_name:
                            node_list.append([equipment_name, equipment_description, equipment_type, operational_state, product_id, serial_number])

                except Exception as e:
                    print(str(e))
                    exit(1)

            else:
                print("Node "+node_name+" has no equipment-list")
                exit()

        print("Node " + node_name + " has " + str(len(node_list)) + " filtered equipments\n")
        print(tabulate(sorted(node_list), headers=(['Equipment Name', 'Equipment Description', 'Equipment Type', 'Operational State',
                                                    'Product ID', 'Serial Number'])),"\n")
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

    getNodeInventory()
