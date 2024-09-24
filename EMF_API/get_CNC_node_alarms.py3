#!/usr/bin/python

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
    url = base_url + "/crosswork/sso/v1/tickets/" + ticket
    response = requests.post(url, headers=headers, params=params, verify=False)
#  If get ticket is ok, no further needs for checking token
    return response.text

######################################
# Following function performs POST
# request on CW API
######################################

def run_post(url, payload):
    print("Executing POST", url)
    auth_headers = {
        'accept': 'application/json',
        'Authorization': token,
    }
    try:
        response = requests.post(url, headers=auth_headers, data=payload, verify=False)
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            return response.text
        print("Could not execute POST " + url)
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run POST "+url)
        exit(1)

    return response.text

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
    node_uuid = ""
    url = base_url + "/restconf/data/v1/cisco-resource-physical:node?name=" + node_name
    node = run_get(url, 'xml')
    try:
        root = ET.fromstring(node)
    except:
        print("Could not extract XML form reply. Exiting")
        exit(1)
    lastIndex = int(root[0][1].text)
    if lastIndex >= 0:
        for node in root[1]:
            try:
                node_uuid = node.find('{urn:cisco:params:xml:ns:yang:resource:device}uuid').text
            except:
                print("node UUID not found")

        return True, node_uuid

    else:
        return False, node_uuid

def getAlarms(node_uuid):
    url = base_url + "/crosswork/alarm-rest-service/v1/alarm-rest/AlarmsByDevices"
    alarm_list = []
    payload = "{\"deviceUUIDs\":[\""+node_uuid+"\"],  \"range\":\"0-100\"}"
    api_output = json.loads(run_post(url, payload))
    if api_output["totalCount"] > 0:
        print("\nNode", node_name, "has", api_output["totalCount"], "alarms\n")
        output_list = api_output["alarms"]
        for alarm in output_list:
            try:
                alarm_severity = alarm["severity"]
            except:
                alarm_severity = "NA"
            try:
                pippo = alarm["description"]
                alarm_description = pippo[0:110]
            except:
                alarm_description = "NA"
            try:
                alarm_category = alarm["applicationCategoryData"]
            except:
                alarm_category = "NA"
            try:
                eventType = alarm["eventType"]
            except:
                eventType = "NA"
            try:
                protocol = alarm["notificationDeliveryMechanism"]
            except:
                protocol = "NA"
            try:
                creationTimestamp = alarm["alarmCreationTime"]
            except:
                creationTimestamp = "NA"
            try:
                updateTimestamp = alarm["lastModifiedTimestamp"]
            except:
                updateTimestamp = "NA"
            try:
                deviceTimestamp = alarm["deviceTimestamp"]
            except:
                deviceTimestamp = "NA"
            alarm_list.append([alarm_severity, alarm_description, alarm_category, eventType, protocol, creationTimestamp,
                               updateTimestamp, deviceTimestamp])
        print(tabulate(sorted(alarm_list), headers=(['Severity', 'Description', 'Category', 'Event Type', 'Protocol',
                                                     'Creation Timestamp', 'Last Update Timestamp', 'Device Timestamp'])))
    else:
        print("No alarms found for node", node_name)

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

    node_found, node_uuid = isNode(node_name)
    if not node_found:
        print("Node",node_name,"not found")
        exit(1)
    print("Node UUID is",node_uuid)

    getAlarms(node_uuid)
