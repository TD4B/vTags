# -*- coding: utf-8 -*-
"""
Created on Sat Feb 17 11:23:22 2018

@author: tdub
"""

import yaml
import requests
import xmltodict, json

# disable insecure SSL warning if interface is set up with a self signed cert.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# vCenter SDK Bindingds & Modules.
from pyVim.connect import SmartConnect, Disconnect
import ssl

# Get login info from configuration file for NSX API.
with open('login.yaml') as yamlfile:
    data = yaml.load(yamlfile)
    nsxhostname, nsxusr, nsxpw = data['NSX']['hostname'],data['NSX']['username'],data['NSX']['password']
    vchostname, vcusr, vcpw = data['vCenter']['hostname'],data['vCenter']['username'],data['vCenter']['password']

# Global Folder Name for Security Groups and Group to Apply NSX Security TAG.
folder = "SomeVCenterFolder"
sectag = "SomeNSXSecurityTag"

s = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
s.verify_mode = ssl.CERT_NONE

c = SmartConnect(host=vchostname, user=vcusr, pwd=vcpw, sslContext=s)
 
print("Executed at System Time: " + str(c.CurrentTime()))

datacenter = c.content.rootFolder.childEntity[0]
vms = datacenter.vmFolder.childEntity

# Main Program Methods.

def detach(sectagid,vmoid):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname+ '/api/2.0/services/securitytags/tag/{}/vm/{}'.format(sectagid,vmoid)
    r = requests.delete(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return r.text

def getsectag(name):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag'
    r = requests.get(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    try:
        o = xmltodict.parse(r.text)
        result = json.dumps(o) 
        jsons = json.loads(result)['securityTags']['securityTag']
        for i in jsons:
            if i['name'] == name:
                print("Name: " + name + " ID: " + i['objectId'])
                val = i['objectId']       
    except:
        print("Error Retreiving SecTAG Data.")
    
    return val

def applytag(sectagid,vmoid):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag/{}/vm/{}'.format(sectagid,vmoid)
    r = requests.put(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return r.text

# Main Program loop.
def main():
# Get Security Tag ID.
    sectagid = getsectag(sectag)
    
    # Get all VM's for the folder.
    foldervm = []
    
    # The first method, the machines need to be detached in order to update the security tag w/ Updated folder members.
    print("Cleaning, Detaching VMs.")
    for i in vms:
        if str(i).split(".")[1].split(":")[0] == "VirtualMachine":
            try:
                vmoid = str(i).split(".")[1].split(":")[1][:-1]
                detach(sectagid,vmoid)
            except:
                print("Error Detaching Virtual Machine!")
                
    # Next the members of the folder are added to the whitelist.
        if i.name == folder:
            for j in i.childEntity:
               foldervm.append(str(j).split(":")[1][:-1])
    
    print("Have Members of the Folder: " + str(foldervm))
    print("Adding Members to Security Tag...")

    for i in foldervm:
        try:
            print("Adding Specific Member: " + i)
            applytag(sectagid,i)
        except:
            print("Failed to Add Members to Security Tag!")
    
    Disconnect(c)
    
if __name__ == "__main__":
    main()    







