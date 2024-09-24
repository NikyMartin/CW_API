#!/usr/bin/python

# This script is meant to change device admin state from UP to DOWN and viceversa in bulk mode
# Tested on CNC rel 7.0

# September 23rd 2024
# First Release

import requests
import json
import urllib3
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
# Following function performs POST
# request on CW API
######################################

def run_post(url):
    print("Executing POST", url)
    auth_headers = {
        'accept': 'application/json',
        'Authorization': token,
    }
    post_payload = "{\r\n\t\"limit\": 100,\r\n\t\"next_from\": \"0\",\r\n\t\"filter\": {\r\n\t}\r\n}"

    try:
        time.sleep(0.01)
        response = requests.post(url, headers=auth_headers, data=post_payload, verify=False)
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

    return response.text

def create_put_payload(device_uuid, device_profile, reach_check, connectivity_info, product_info,
                                             routing_info, mapped_dg, device_name,  providers, admin_state):
    put_payload = json.loads('{"data": [{}]}')
    put_payload["data"][0].update({"admin_state": admin_state})
    put_payload["data"][0].update({"uuid": device_uuid})
    put_payload["data"][0].update({"host_name": device_name})
    put_payload["data"][0].update({"profile": device_profile})
    put_payload["data"][0].update({"reachability_check": reach_check})
    put_payload["data"][0].update({"connectivity_info": connectivity_info})
    put_payload["data"][0].update({"product_info": product_info})
    put_payload["data"][0].update({"mapped_dg": mapped_dg})
    put_payload["data"][0].update({"routing_info": routing_info})
    if providers != "NA":
        put_payload["data"][0].update({"providers_family": providers})

    return put_payload

######################################
#               START
######################################

def change_admin_state(admin_state):
    url = base_url + "/crosswork/inventory/v1/nodes/query"
    api_output = json.loads(run_post(url))
    try:
        nodes = api_output["data"]
    except:
        print("data not found in API output. Exiting")
        delete_ticket()
        exit()
    print("\nFound "+str(len(nodes))+" nodes")
    index = 0
    completed_count = 0
    failed_count = 0
    warning_count = 0
    skip_count = 0
    url = base_url + "/crosswork/inventory/v1/nodes"
    for node in nodes:
        index += 1
        print("\nNode # "+str(str(index)))
        try:
            orig_state = node["admin_state"]
            device_uuid = node["uuid"]
            device_name = node["host_name"]
            device_profile = node["profile"]
            reach_check = node["reachability_check"]
            connectivity_info = node["connectivity_info"]
            product_info = node["product_info"]
            routing_info = node["routing_info"]
            mapped_dg = node["dg_uuid"]
            state_found = True
        except:
            print("Cannot parse node "+str(index)+" from the list. Skipping")
            skip_count += 1
            state_found = False

### If device is onboarded without providers, setting providers to "NA"

        try:
            providers = node["providers_family"]
        except:
            print("NOTE: Providers not found for "+device_name+". Proceeding anyway")
            providers = "NA"

        if state_found:

### Device is Maintenance or other states

            if orig_state != "ROBOT_ADMIN_STATE_UP" and orig_state != "ROBOT_ADMIN_STATE_DOWN":
                print("State for node "+str(index)+" is "+orig_state+" Skipping")
                skip_count += 1


### From UP to DOWN

            if orig_state == "ROBOT_ADMIN_STATE_UP":
                if input_state == "1":
                    print("State for " + device_name + " already UP. Skipping")
                    skip_count += 1
                else:
                    print("State for " + device_name + " is UP . Changing state to DOWN")
                    admin_state = "ROBOT_ADMIN_STATE_DOWN"
                    put_payload = create_put_payload(device_uuid, device_profile, reach_check, connectivity_info,
                                                     product_info, routing_info, mapped_dg, device_name, providers,
                                                     admin_state)
                    api_output = json.loads(run_put(url, json.dumps(put_payload)))
                    job_state = api_output["state"]

                    print("Job State is: " + job_state)
                    if job_state == "JOB_FAILED":
                        print("Error: "+api_output["error"])
                        failed_count += 1
                    if job_state == "JOB_COMPLETED_WITH_WARNING":
                        print(api_output["error"])
                        warning_count += 1
                    if job_state == "JOB_COMPLETED":
                        completed_count += 1
                   # print(json.dumps(put_payload, indent=4))

### From DOWN to UP

            if orig_state == "ROBOT_ADMIN_STATE_DOWN":
                if input_state == "2":
                    print("State for node "+ device_name + " already DOWN. Skipping")
                    skip_count += 1
                else:
                    print("State for node " + device_name +  " is DOWN. Changing state to UP")
                    admin_state = "ROBOT_ADMIN_STATE_UP"
                    put_payload = create_put_payload(device_uuid, device_profile, reach_check, connectivity_info,
                                                     product_info, routing_info, mapped_dg, device_name,  providers,
                                                     admin_state)
                    api_output = json.loads(run_put(url, json.dumps(put_payload)))
                    job_state = api_output["state"]

                    print("Job State is: " + job_state)
                    if job_state == "JOB_FAILED":
                        print("Error: "+api_output["error"])
                        failed_count += 1
                    if job_state == "JOB_COMPLETED_WITH_WARNING":
                        print(api_output["error"])
                        warning_count += 1
                    if job_state == "JOB_COMPLETED":
                        completed_count += 1

    print("\nFound " + str(len(nodes)) + " nodes")
    print("Completed Jobs: "+str(completed_count))
    print("Failed Jobs: " + str(failed_count))
    print("Warning Jobs: " + str(warning_count))
    print("Skipped: " + str(skip_count))
    # print(json.dumps(api_output, indent=4))

################################
#           MAIN
################################
if __name__ == "__main__":
    if len(sys.argv)!=5:
       print('\nSyntax must be: change_state_bulk.py <CNC IP> <CNC Username> <CNC User Password> and 1 for UP or 2 for DOWN\n')
       exit()
    scripts, server_ip, username, password, input_state = sys.argv

    if input_state not in ["1","2"]:
        print("\nInput State can only be 1 for UP or 2 for DOWN")
        print("Syntax must be: change_state_bulk.py <CNC IP> <CNC Username> <CNC User Password> and 1 for UP or 2 for DOWN\n")
        exit()

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

    change_admin_state(input_state)

    delete_ticket()

    print("\n#### Script Execution Completed !!! ####\n")