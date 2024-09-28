#!/usr/bin/python

# This script leverages CNC RESTCONF API to retrieve all active alarms on a give node
# It uses different resource endpoints depending on the CNC release
# CNC 6.0   /restconf/data/v1/cisco-rtm:alarm
# CNC 7.0   /crosswork/alarm/restconf/data/v2/rtm:alarm
# Although still working, v1 has been deprecated in CNC 7.0
# In CNC 7.0 MD changed form CISCO_EPNM to CISCO_EMS, thus v1 cant be used anyway
# Need to add pagination. That means it works with less then 100 entries for now
#
# Tested on CNC rel 7.0, both SVM and cluster based installs
# Tested on CNC 6.0 and 7.0
#
# September 28th 2024
# Added CNC version control and Device Timestap
#
# September 27th 2024
# First Release
#
# Syntax: get_CNC_node_alarms.py3 <CNC IP> <CNC_port> <CNC Username> <CNC user Password> <Node_Name>
#

import requests
import json
import urllib3
from tabulate import tabulate
import sys
import socket
import urllib
import time
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######################################
#           Variables
######################################

now = datetime.now()

headers = {
    'Accept': 'text/plain',
    'Cache-Control': 'no-cache',
    'Content-Type': 'application/x-www-form-urlencoded',
}

def timeStamp():
    current_time = now.strftime("%H:%M:%S")
    print("\nServer Time =", current_time)

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
        print("Could not execute GET " + url)
        if response.status_code == 400:
            try:
                error_message = json.loads(response.text)["rc.errors"]["error"]["error-message"]
                print()
                print(error_message)
            except:
                placeholder = ""

            print("\nIf Status Code is 404, it can be common EMF cAPP is not installed")
            delete_ticket()
            exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run GET "+url)
        delete_ticket()
        exit(1)

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

    try:
        time.sleep(0.01)
        response = requests.post(url, headers=auth_headers, verify=False)
        print("Status Code: ", response.status_code)
        if 200 <= response.status_code <= 210:
            return response.text
#        print(response.text) should be parsed. It wont print as is
        print("Could not execute POST "+url)
        print("\nIf Status Code is 404, it can be common inventory cAPP is not installed\n")
        exit(1)
    except Exception as e:
        print(str(e))
        print("Cannot run POST "+url)
        exit(1)

    return response.text

######################################
# Following function returns first 3
# characters from INFRA version
# Ex: 6.0 or 7.0
######################################
def get_CNC_Version():
    url = base_url + "/crosswork/platform/v2/capp/applicationdata/query"
    api_output = json.loads(run_post(url))
    app_list = api_output["application_data_list"]
    for application in app_list:
        app_name = application["application_id"]
        if app_name == "capp-infra":
            infra_version = application["version"][:3]
    #print(json.dumps(result, indent=4))

    return infra_version

######################################
#               START
######################################

def parse_alarms(alarms):
    alarm_list = [] # inizializing alarm list
    for alarm in alarms:
        try:
            alarm_severity = alarm["alm.perceived-severity"]
        except:
            alarm_severity = "NA"
        try:
            alarm_description = alarm["alm.description"]
        except:
            alarm_description = "NA"
        try:
            event_type = alarm["alm.probable-cause"]
        except:
            event_type = "NA"
        try:
            source_object = alarm["alm.source-object-name"]
        except:
            source_object = "NA"
        try:
            creationTimestamp = alarm["alm.system-received-time"]
        except:
            creationTimestamp = "NA"
        try:
            deviceTimestamp = alarm["alm.node-event-time"]
        except:
            deviceTimestamp = "NA"

        alarm_list.append([alarm_severity, alarm_description, event_type, source_object, creationTimestamp,
                           deviceTimestamp])

    return(alarm_list)

def get_node_alarms(node_name, infra_version):
    if infra_version == "6.0":
       url = base_url + "/restconf/data/v1/cisco-rtm:alarm?alarmtype=device&nd-ref=MD=CISCO_" \
                         "EPNM!ND=" + node_name + "&perceived-severity=critical,major,minor,warning"
    if infra_version == "7.0":
       url = base_url + "/crosswork/alarm/restconf/data/v2/rtm:alarm?alarmtype=device&nd-ref=MD=CISCO_" \
                     "EMS!ND=" + node_name + "&perceived-severity=critical,major,minor,warning"

    api_output = json.loads(run_get(url, "json"))
    lastIndex = api_output["com.response-message"]["com.header"]["com.lastIndex"]

    if lastIndex == -1: # Control if output has no alarms
        print("No alarm found. Exiting")
        delete_ticket()
        exit()

    alarms = api_output["com.response-message"]["com.data"]["alm.alarm"]
    alarm_list = parse_alarms(alarms)

    print("\nNode", node_name, "has", len(alarm_list), "alarms\n")
    print(tabulate(sorted(alarm_list), headers=(['Severity', 'Description', 'Event Type', 'Managed Object',
                                                 'Creation Timestamp', 'Device Timestamp'])))



######################################
#               MAIN
######################################
if __name__ == "__main__":
    if len(sys.argv)!=6:
       print('\nSyntax must be: get_CNC_node_alarms.py3 <CNC IP> <CNC_port> <CNC Username> <CNC user Password> '
             '<Node_Name>\n')
       exit()
    scripts, server_ip, cw_port_string, username, password, node_name = sys.argv

    try:
        cw_port = int(cw_port_string)
    except:
        print(str(cw_port) + " is not an integer. Exiting")
        exit()

    if not (1024 <= cw_port <= 65535):
        print(str(cw_port) + " not in [1040 - 65535] range. Exiting")
        exit()

# Decode password from HTML to non-ASCI
    password = urllib.parse.unquote(password)

    timeStamp()
    print("\nChecking Server Port")
    if not isOpen(server_ip, cw_port):
        print("\nERROR: " + server_ip + " is not reachable, either the server is down or port " + str(cw_port)
              + " is filtered\n")
        exit()

    base_url = "https://" + server_ip + ":" + cw_port_string
    ticket = get_ticket()
    token = get_token()

    cnc_version = get_CNC_Version()
    if cnc_version not in ["6.0", "7.0"]:
        print("\nThis script has been only validated against releases 6.0 and 7.0")
        print("Current version is " + cnc_version + " Exiting")
        delete_ticket()
        print()
        exit()

    get_node_alarms(node_name, cnc_version)

    delete_ticket()

    print("\n#### Script Execution Completed !!! ####\n")