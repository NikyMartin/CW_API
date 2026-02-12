#!/bin/bash

#################################################################################
#
# ztpSampleScriptFile.sh
#
# Purpose: This sample script is required to provide status notification of ZTP 
# process on IOS XR device, and update IP address, hostname to Crosswork. It is 
# also used to download day0 config file from Crosswork config repository and 
# apply initial configuration on device. 
# 
# Procedure: Modify sample script as below, upload to Crosswork config 
# repository. Next, copy URL of this file from repository & set value in DHCP 
# server boot filename for ZTP config download. When ZTP is triggered on device, 
# it will download & run script, then notify Crosswork.
#  
# Replace following variables with valid values & upload to Crosswork config 
# repository. Sample values are provided for reference.
# - XRZTP_INTERFACE_NAME: e.g., MgmtEth0/RP0/CPU0/0 interface where ZTP triggered 
# - CW_HOST_IP: Crosswork VM management or data network IP address,
# - CW_PORT: 30604 for HTTP & 30603 only for HTTPS download of config file
# - CW_CONFIG_UUID: Replace with UUID of day0 config file from Crosswork repo,
#   assuming user has already uploaded device day-0 config file.
#
# This script has been tested on Cisco NCS5501, NCS540l, ASR9901, 8800 routers.
# 
#################################################################################


export LOGFILE=/disk0:/ztp/customer/user-script.log

XRZTP_INTERFACE_NAME="MgmtEth0/RP0/CPU0/0"
# ZTP helper library is assumed to be installed in IOS-XR linux shell
source /pkg/bin/ztp_helper.sh
interfacedata=$(xrcmd "show interface ${XRZTP_INTERFACE_NAME}")

CW_HOST_IP="198.18.1.221"
CW_PORT="30604"
CW_CONFIG_UUID="66e92f1e-1100-4f03-b4b6-e07be64f14a2"

# Send logging information to log file on device disk0:/ztp/user-script.log
function ztp_log() {

    echo "$(date +"%b %d %H:%M:%S") "$1 >> $LOGFILE
}

# 
# Get chassis serial number of the device, required by ZTP process.
# This works on Cisco NCS5501, NCS540l, 8800 series routers.
#
function get_serialkey(){

    # local sn=$(dmidecode | grep -m 1 "Serial Number:" | awk '{print $NF}');
    # local sn=$(xrcmd 'show license udi' | grep SN: | awk -F: '{print $NF}');
    
    # 14-01-2026: nmartino update for dcloud lab
    local sn=$(xrcmd 'show inventory' | grep IOSXRV9000-CC | awk '{print $NF}');
    
    if [ "$sn" != "Not found" ]; then
           ztp_log "Serial $sn found.";
           # The value of $sn from dmidecode should be same as serial number
           # of XR device chassis. 
           DEVNAME=$sn;
           return 0
    else
        ztp_log "Serial $sn not found.";
        return 1
    fi
}

# 
# Get chassis serial number of the device, required by ZTP process.
# This is tested, works on Cisco ASR 9901, not other devices!
#
function get_serialkey_asr9901(){

     udi=$(xrcmd "show license udi")
     sn="$(cut -d':' -f4 <<<"$udi")"
     pid="$(cut -d':' -f3 <<<"$udi")"
     pid="$(cut -d',' -f1 <<<"$pid")"
     echo "Serial Number $sn"
     echo "product id $pid"
}

# 
# Get IP address and subnet mask from device. IP address is assigned from DHCP 
# server on interface where ZTP was triggered.
#
function get_ipaddress(){

    local ipvar=($(echo $interfacedata | awk -F "Internet address is " '{sub(/ .*/,"",$2);print $2}'));
    local ipv4addr=$(xrcmd "sh run interface ${XRZTP_INTERFACE_NAME} | i ipv4 address" | awk '{print $3}')
    local ipv6addr=$(xrcmd "sh run interface ${XRZTP_INTERFACE_NAME} | i ipv6 address" | awk '{print $3}')
    local ipaddress=($(echo $ipvar | awk -F "/" '{sub(/ .*/,"",$1);print $1}'));
    local mask=($(echo $ipvar | awk -F "/" '{sub(/ .*/,"",$2);print $2}'));
    local maskv6=($(echo $ipv6addr | awk -F "/" '{sub(/ .*/,"",$2);print $2}'));

    ztp_log "### Value of interfacedata => $interfacedata ###"
    ztp_log "### Value of ipvar => $ipvar ###"
    ztp_log "#####IPv4 address $ipaddress and mask $mask found. #####";

    IPADDR=$ipaddress
    MASK=$mask
    MASKV6=$maskv6

    return 0
}

#
# Fetch hostname from device configuration.
#
function get_hostname(){

    hostnamedata=$(xrcmd "show running-config hostname")
    local hostname=($(echo $hostnamedata | awk -F "hostname " '{sub(/ .*/,"",$2);print $2}'));

    ztp_log "#####hostname $hostname found.";
    HOSTNAME=$hostname;
    return 0;
}

#
# Download day-0 config file from Crosswork config repository using values 
# set for CW_HOST_IP, CW_PORT and CW_CONFIG_UUID.  
# The MESSAGE variable is optional, can be used to display suitable message 
# based on ZTP success/failure log.
#
function download_config(){

    ztp_log "### Downloading system configuration ::: ${DEVNAME} ###";
    ztp_log "### ip address passed value ::: ${IPADDR} ###";
    ip netns exec global-vrf /usr/bin/curl -k --connect-timeout 60 -L -v --max-filesize 104857600 http://${CW_HOST_IP}:${CW_PORT}/crosswork/configsvc/v1/configs/device/files/${CW_CONFIG_UUID} -H X-cisco-serial*:${DEVNAME} -H X-cisco-arch*:x86_64 -H X-cisco-uuid*: -H X-cisco-oper*:exr-config -o /disk0:/ztp/customer/downloaded-config 2>&1

    if [[ "$?" != 0 ]]; then
        STATUS="ProvisioningError"
        ztp_log "### status::: ${STATUS} ###"
        ztp_log "### Error downloading system configuration, please review the log ###"
        MESSAGE="Error downloading system configuration"
    else
        STATUS="Provisioned"
        ztp_log "### status::: ${STATUS} ###"
        ztp_log "### Downloading system configuration complete ###"
        MESSAGE="Downloading system configuration complete"
    fi
}

#
# Apply downloaded configuration to the device and derive ZTP status based on
# success/failure of ZTP process. The MESSAGE variable is optional, can be used 
# to display suitable message based on ZTP success/failure log.
#
function apply_config(){
    ztp_log "### Applying initial system configuration ###";
    xrapply_with_reason "Initial ZTP configuration" /disk0:/ztp/customer/downloaded-config 2>&1 >> $LOGFILE;
    ztp_log "### Checking for errors ###";
    local config_status=$(xrcmd "show configuration failed");
    if [[ $config_status ]]; then
        echo $config_status  >> $LOGFILE
        STATUS="ProvisioningError"
        ztp_log "### status::: ${STATUS} ###"
        ztp_log "!!! Error encountered applying configuration file, please review the log !!!!";
        MESSAGE="Error encountered applying configuration file, ZTP process failed"
    else
       STATUS="Provisioned"
       ztp_log "### status::: ${STATUS} ###"
       ztp_log "### Applying system configuration complete ###";
       MESSAGE="Applying system configuration complete, ZTP process completed"
   fi
}

# 
# Call Crosswork ZTP API to update device ZTP status, IP address, hostname.
# Without this function, device status will remain in "In Progress" and not 
# be updated in Crosswork.
#
# Using this API, device SSH/SNMP connectivity details can also be updated.
# Values for connectivity details values can be added as part of 
# "connectivityDetails" array in below curl command. Sample snippet provided:
#
#   "connectivityDetails": [{
#     "protocol": "SSH",
#     "inetAddr": [{
#       "inetAddressFamily": "IPV4/IPV6",
#       "ipaddrs": "<ssh/snmp ipaddress>",
#       "mask": <ipaddress mask(Integer).>,
#       "type": "CONNECTIVITYINFO"
#     }],
#     "port": <ssh/snmp port(Integer)>,
#     "timeout": <ssh/snmp timeout(Integer). default to 60sec>
#   }]
#
function update_device_status() {

     echo "'"$IPADDR"'"
     echo "'"$MASK"'"
     echo "'"$DEVNAME"'"
     echo "'"$STATUS"'"
     echo "'"$HOSTNAME"'"
     echo "'"$MESSAGE"'"


    curl -d '{
       "ipAddress":{
            "inetAddressFamily": "IPV4",
            "ipaddrs": "'"$IPADDR"'",
            "mask":  '$MASK'
        },
       "serialNumber":"'"$DEVNAME"'", 
       "status":"'"$STATUS"'", 
       "hostName":"'"$HOSTNAME"'",
       "message":"'"$MESSAGE"'"
   }' -H "Content-Type: application/json" -X PATCH http://${CW_HOST_IP}:${CW_PORT}/crosswork/ztp/v1/deviceinfo/status
}


# ==== Script entry point ====
STATUS="InProgress"
get_serialkey;
#get_serialkey_asr9901; // For Cisco ASR9901, replace get_serialkey with get_serialkey_asr9901.
ztp_log "Hello from ${DEVNAME} !!!";
get_ipaddress;
ztp_log "Starting autoprovision process...";
download_config;
apply_config;
get_hostname;
update_device_status;

ztp_log "Autoprovision complete...";
exit 0
