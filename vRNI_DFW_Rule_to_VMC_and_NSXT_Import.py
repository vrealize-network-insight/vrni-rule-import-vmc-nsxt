#################################################################################
#                                                                               #
#  The purpose of this script is to import firewall rules exported by vRNI to   #
#  either a SDDC deployed in VMware VMC on AWS, or NSX-T Manager                #
#                                                                               #
#################################################################################


### Package Imports ####
import requests
import json
import argparse
import sys
import re
import requests
from requests_toolbelt.utils import dump
import glob
import os
from os import listdir, path
from xml.dom import minidom
from xml.dom.minidom import parse, parseString
import xml.etree.ElementTree as ET
import getpass
import csv

#IgnoreSelfSignedSSLCerts
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class VMCRuleImport():
    """Main class for importing VMC DFW Rules"""
    ### Arguments ###
    def __init__(self):
            self.verbose = False
            self.orgid = None
            self.sddcid = None
            self.refreshtoken = None
            self.rulefolder = None
            self.applicationname = None
            self.enablerules = True
            self.nsxt = False
            self.vmc = False
            self.nsxturl = None
            self.nsxtusername = None
            self.nsxtpassword = None
            self.nsxtauthvalues = None
            self.csvfile = None

    def main(self):
        """Starting point for import process"""
        parser = argparse.ArgumentParser(description='Export user created NSX-T Firewall rules and objects for a given VMC SDDC.', add_help=False)
        parser.add_argument('--help', '-?', dest="help", action='store_true', help='Print this usage message')
        parser.add_argument('--orgid', '-o', help='VMC organizational ID')
        parser.add_argument('--rulefolder', '-f', help='Folder directory location')
        parser.add_argument('--sddcid', '-s', help='SDDC ID')
        parser.add_argument('--refreshtoken', '-r', help='Generated API token')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output (print status messages)')
        parser.add_argument('--appname', '-a', help='Name of application for imported rules without spaces')
        parser.add_argument('--enablerules', action='store_false', help='Creates enabled firewall rules.  Default is disabled.')
        parser.add_argument('--nsxturl', '-n' , help='URL of NSX-T Manager or VIP')
        parser.add_argument('--nsxtuser', '-u', help='NSX-T Username')
        parser.add_argument('--securitygroupcsv' , help="CSV File containing Security Group Members **For vRNI versions 6.2+**")
        args = parser.parse_args()
        if args.help:
            parser.print_help()
            sys.exit(1)

        self.verbose = args.verbose
        self.orgid = args.orgid
        self.sddcid = args.sddcid
        self.refreshtoken = args.refreshtoken
        self.rulefolder = args.rulefolder
        self.applicationname = args.appname
        self.enablerules = args.enablerules
        self.nsxturl = args.nsxturl
        self.nsxtusername = args.nsxtuser
        self.csvfile = args.securitygroupcsv

        targettype = input("Is target DFW NSX-T (1) or NSX on VMC (2).  Please input 1 for NSX-T or 2 for NSX on VMC: ")
        if targettype == '1':
             self.nsxt = True
             if self.verbose:
                print("Your target destination for rules will be NSX-T")
        if targettype == '2':
            self.vmc = True
            if self.verbose:
                print("Your target destination for rules will be VMC")
        if targettype != '1' and targettype != '2':
            print("Invalid argument, Please input 1 for NSX-T or 2 for NSX on VMC")
            sys.exit(1)

        if self.vmc:
            if not self.orgid:
                self.orgid = input('Please provide organization ID:  ')
            if not self.sddcid:
                self.sddcid = input('Please provide SDDC ID:  ')
            if not self.refreshtoken:
                self.refreshtoken = input('Please provide API Token:  ')
        
        if self.nsxt:
            if not self.nsxturl:
                self.nsxturl = input('Please provide NSX-T Manager or VIP URL:  ')
            if not self.nsxtusername:
                self.nsxtusername = input('Please provide the NSX-T username:  ')
            self.nsxtpassword = getpass.getpass('Please enter NSX-T password for username ' + self.nsxtusername + ":  ")
            self.nsxtauthvalues = (self.nsxtusername, self.nsxtpassword)

        if not self.rulefolder:
            self.rulefolder = input('Please input rule folder location: ')
        if not self.applicationname:
            self.applicationname = input('Please input name of application for imported rules without spaces:  ')
        if not self.csvfile:
            while True:
                creategroupsanswer = input('Would you like to populate created security groups with member IP addresses? **For vRNI versions 6.2 and up only** (y/n)')
                if creategroupsanswer.lower() not in ('y', 'n'):
                    print("Please answer with 'y' or 'n'")
                else: 
                    break
            if creategroupsanswer.lower() == ('y'):
                self.csvfile = input('Please input the location of the export-members.csv file')

    ### Functions run order ###
        if self.vmc:
            self.gettoken()
            self.getproxyurls()
        self.getfirewallsectionids()
        self.createfirewallrulesection()
        self.getsecuritygroups()
        self.parsetiers()
        self.createsecuritygroups()
        self.getsecuritygroups()  
        if self.csvfile:
            self.populatesecuritygroups()  
        self.getservicesdefinitions()
        self.creatservicesdefinitions()
        self.getservicesdefinitions()
        self.createrules()

    ### Functions to get existing configurations ###

    def gettoken(self):
        authurl = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' %(self.refreshtoken)
        headers = {'Accept': 'application/json'}
        payload = {}
        response = requests.post(authurl,headers=headers,data=payload)
        authjson = json.loads(response.text)
        self.token = authjson["access_token"]
        if self.verbose:
            print("Access token: ")
            print(self.token, "\n")
            if response.status_code != 200:
                print("Unable to obtain access token. Response: ", response.status_code, "\n")

    def getproxyurls(self):
        infourl = 'https://vmc.vmware.com/vmc/api/orgs/%s/sddcs/%s' %(self.orgid, self.sddcid)
        headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
        payload = {}
        response = requests.get(infourl,headers=headers,data=payload)
        sddcjson = json.loads(response.text)
        self.srevproxyurl = sddcjson["resource_config"]["nsx_api_public_endpoint_url"]
        self.nsxpolicymanagerurl = sddcjson["resource_config"]["nsx_mgr_url"]
        if self.verbose:
            print("VMC Reverse Proxy URL: ")
            print(self.srevproxyurl , '\n')
            print("NSX Policy Manager URL: ")
            print(self.nsxpolicymanagerurl, '\n')
            if response.status_code != 200:
                print("Unable get URLs. Response: ", response.status_code, "\n")

    def getfirewallsectionids(self):
        if self.vmc:
            infourl = '%s/policy/api/v1/infra/domains/cgw/communication-maps' %(self.srevproxyurl)
            headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
            payload = {}
            response = requests.get(infourl, headers=headers, data=payload)
        if self.nsxt:
            infourl = '%spolicy/api/v1/infra/domains/default/communication-maps' %(self.nsxturl)
            headers = {'content-type': 'application/json'}
            payload = {}            
            response = requests.get(infourl, auth=self.nsxtauthvalues, verify=False, headers=headers, data=payload)
        d = json.loads(response.text)
        self.existingcommunicationmaps = d
        self.communicationmaps = []
        for value in self.existingcommunicationmaps.get("results"):
            self.communicationmaps.append(value.get("id"))
        if self.verbose:
            if response.status_code == 200:
                print("Retrieved policy sections \n")
            else: 
                print("Unable to get exisitng policy sections: Response: ", response.status_code, "\n")

    def getsecuritygroups(self):
        existinggroups = []
        cursor = None
        while True:
            if self.vmc:
                if not cursor:
                    infourl = '%s/policy/api/v1/infra/domains/cgw/groups' %(self.srevproxyurl)
                if cursor:
                    infourl = '%s/policy/api/v1/infra/domains/cgw/groups?cursor=%s' %(self.srevproxyurl, cursor)
                headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
                payload = {}
                response = requests.get(infourl, headers=headers, data=payload)
                d = json.loads(response.text)
                existinggroups = existinggroups + d["results"]
                cursor = d.get('cursor', None)
                if cursor == None:
                    break
            if self.nsxt:
                if not cursor:
                    infourl = '%spolicy/api/v1/infra/domains/default/groups' %(self.nsxturl)
                if cursor:
                    infourl = '%spolicy/api/v1/infra/domains/default/groups?cursor=%s' %(self.nsxturl, cursor)
                headers = {'content-type': 'application/json'}
                payload = {}
                response = requests.get(infourl, auth=self.nsxtauthvalues, verify=False, headers=headers, data=payload)
                d = json.loads(response.text)
                existinggroups = existinggroups + d["results"]
                cursor = d.get('cursor', None)
                if cursor == None:
                    break
        self.secgrouplist = []
        self.secgroupids = []
        for item in existinggroups:
            if item.get('id').endswith('-vRNI-Import-Tier'):
                secid = item.get('id')
                secpath = item.get('path')
                self.secgrouplist.append({'section id': secid, 'Path': secpath})
                self.secgroupids.append(secid)
        if self.verbose:
            if response.status_code == 200:
                print("Retrieved security groups \n")
            else:
                print("Unable to retrieve security groups. Response: ", response.status_code ,'\n')

    def getservicesdefinitions(self):
        existingservices = []
        cursor = None
        while True:
            if self.vmc: 
                if not cursor:
                    infourl = '%s/policy/api/v1/infra/services' %(self.srevproxyurl)
                if cursor:
                    infourl = '%s/policy/api/v1/infra/services?cursor=%s' %(self.srevproxyurl, cursor)
                headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
                payload = {}
                response = requests.get(infourl, headers=headers, data=payload)        
                d = json.loads(response.text)
                existingservices = existingservices + d["results"]
                cursor = d.get('cursor', None)
                if cursor == None:
                    break
            if self.nsxt:
                if not cursor: 
                    infourl = '%spolicy/api/v1/infra/services' %(self.nsxturl)
                if cursor: 
                    infourl = '%spolicy/api/v1/infra/services?cursor=%s' %(self.nsxturl, cursor)
                headers = {'content-type': 'application/json'}
                payload = {}
                response = requests.get(infourl, auth=self.nsxtauthvalues, verify=False, headers=headers, data=payload)
                d = json.loads(response.text)
                existingservices = existingservices + d["results"]
                cursor = d.get('cursor', None)
                if cursor == None:
                    break
        self.serviceslookup =[]
        self.existingservices =[]
        for rule in existingservices:
            if rule.get('id').endswith("-vRNI-Import"):
                self.existingservices.append(rule.get('id'))
                ruleid = rule.get('id')
                path = rule.get('path')
                serviceentries = rule.get('service_entries')
                for detail in serviceentries:
                    protocol = detail.get('l4_protocol')
                    port = detail.get('destination_ports')
                fullservice={'id':ruleid, 'Path': path, "Port": port, "Protocol": protocol}
                self.serviceslookup.append(fullservice)
        if self.verbose:
            if response.status_code == 200:
                print("Retrieved service definitions \n")
            else:
                print("Unable to retrieve service definitions. Response: ", response.status_code ,'\n')

    ### Functions for creating new VMC configurations ###
    def createsecuritygroups(self):
        if self.verbose:
            print("******* \n Creating security groups. \n******* \n")
        for tier in self.newsecgroups:
            tiername = tier + "-vRNI-Import-Tier"
            if tiername in self.secgroupids:
                print("Security group for ", tiername, " already created.  Skipping. \n")
                continue
            else:
                if self.vmc:
                    infourl = '%spolicy/api/v1/infra/domains/cgw/groups/%s' %(self.nsxpolicymanagerurl, tiername)
                    headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                    payload = {"resource_type": "Group", "id": tiername , "display_name": tiername, "_protection": "NOT_PROTECTED", "_revision": 0}
                    response = requests.patch(infourl,headers=headers,data=json.dumps(payload))
                if self.nsxt:
                    infourl = '%spolicy/api/v1/infra/domains/default/groups/%s' %(self.nsxturl, tiername)
                    headers = {'content-type': 'application/json'}
                    payload = {"resource_type": "Group", "id": tiername , "display_name": tiername, "_protection": "NOT_PROTECTED", "_revision": 0}
                    response = requests.patch(infourl, auth=self.nsxtauthvalues, verify=False, headers=headers,data=json.dumps(payload))
                if self.verbose:
                    if response.status_code != 200:
                        print("Unable to create new security group " + tiername + ". Response: ", response.status_code, "\n")
                    else:
                        print("Security Group Created: " + tiername, "\n")
    
    def populatesecuritygroups(self):
        if self.verbose:
            print("******* \n Populating Creating security groups. \n******* \n")
        name_regex1 = re.compile(r'([^ ]+) \[Application: ([^\]]+)]')
        name_regex2 = re.compile(r'^Others_(.*)')
        with open(self.csvfile) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # convert all list strings into lists, removing any empty items
                modify = {k: list(filter(None, v.split(', '))) if k != 'Group Name' else v for k,v in row.items()}
                match = name_regex1.match(modify.get('Group Name'))
                match2 = name_regex2.match(modify.get('Group Name'))
                if match:
                    modify['Group Name'] = f'{match.group(2)}-{match.group(1)}-vRNI-Import-Tier'
                    modify['Group Name'] = modify['Group Name'].replace(" ", "-")
                if match2:
                    modify['Group Name'] = f'Others_{match2.group(1)}-vRNI-Import-Tier'
                if modify['Group Name'] in self.secgroupids:
                    print('Populating security group ', modify['Group Name'], '\n')
                    allips = modify['Virtual IPs']
                    allips.extend(modify['Physical IPs'])
                    if self.vmc:
                        infourl = '%spolicy/api/v1/infra/domains/cgw/groups/%s' %(self.nsxpolicymanagerurl, modify['Group Name'])
                        headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                        payload = {"expression": [{"ip_addresses": modify['Virtual IPs'], "resource_type": "IPAddressExpression"}]}
                        response = requests.patch(infourl,headers=headers,data=json.dumps(payload))
                        if self.verbose:
                            if response.status_code != 200:
                                print(response.content)
                            else:
                                print("Security Group populated with IPs: " , allips , "\n")
                    if self.nsxt:
                        infourl = '%spolicy/api/v1/infra/domains/default/groups/%s' %(self.nsxturl, modify['Group Name'])
                        headers = {'content-type': 'application/json'}
                        payload = {"expression": [{"ip_addresses": modify['Virtual IPs'], "resource_type": "IPAddressExpression"}]}
                        response = requests.patch(infourl, auth=self.nsxtauthvalues, verify=False, headers=headers,data=json.dumps(payload))
                        if self.verbose:
                            if response.status_code != 200:
                                print(response.content)
                            else:
                                print("Security Group populated with IPs: " , allips , "\n")

    def createfirewallrulesection(self):
        if self.verbose:
            print("******* \n Creating firewall rule section. \n******* \n")
        self.applicationid = self.applicationname + "-vRNIImport"
        if self.applicationid in self.communicationmaps:
            if self.verbose:
                print("Application communication map already exists: ", self.applicationid , ", skipping to create groups \n")
        else:
            if self.vmc:
                infourl = '%spolicy/api/v1/infra/domains/cgw/communication-maps/%s' %(self.nsxpolicymanagerurl, self.applicationid)
                headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                payload = {"precedence": "1", "category": "Application", "resource_type": "CommunicationMap", "id": self.applicationid, "display_name": self.applicationname}
                response = requests.put(infourl,headers=headers,data=json.dumps(payload))
            if self.nsxt:
                infourl = '%spolicy/api/v1/infra/domains/default/communication-maps/%s' %(self.nsxturl, self.applicationid)
                headers = {'content-type': 'application/json'}
                payload = {"precedence": "1", "category": "Application", "resource_type": "CommunicationMap", "id": self.applicationid, "display_name": self.applicationname}
                response = requests.put(infourl,auth=self.nsxtauthvalues, verify=False, headers=headers,data=json.dumps(payload))
            fwrulesection = json.loads(response.text)
            self.sectionid = fwrulesection["id"]
            if self.verbose:
                if response.status_code != 200:
                    print("Unable to create new communication map. Response: ", response.status_code, "\n")
                else:
                    print("Created policy section: ", self.sectionid, "\n")

    def creatservicesdefinitions(self):
        if self.verbose:
            print("******* \n Creating service definitions. \n******* \n")
        self.services = []
        for line in glob.glob(os.path.join(self.rulefolder,"*FIRE*.xml")):
            dom = minidom.parse(line)
            services = [ x.getElementsByTagName('name')[0].firstChild.nodeValue for x in dom.getElementsByTagName('services')[0].getElementsByTagName('service') ]
            self.services.extend(services)
        self.services = list(dict.fromkeys(self.services))
        for service in self.services:
            service = service.split()
            service = service[0]
            serviceid =  service + "-vRNI-Import"
            if serviceid not in self.existingservices:
                splitservice = service.split('-', 2)
                if self.vmc:
                    infourl = '%spolicy/api/v1/infra/services/%s' %(self.nsxpolicymanagerurl, serviceid)
                    headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                    payload = {"is_default": "true", "service_entries": [{"l4_protocol": splitservice[1], "source_ports": [], "destination_ports": [splitservice[2]], "resource_type": "L4PortSetServiceEntry", "id": serviceid, "display_name": serviceid, "marked_for_delete": 'false', "_protection": "NOT_PROTECTED", "_revision": 0}]}
                    response = requests.patch(infourl,headers=headers,data=json.dumps(payload))
                if self.nsxt:
                    infourl = '%spolicy/api/v1/infra/services/%s' %(self.nsxturl, serviceid)
                    headers = {'content-type': 'application/json'}
                    payload = {"is_default": "true", "service_entries": [{"l4_protocol": splitservice[1], "source_ports": [], "destination_ports": [splitservice[2]], "resource_type": "L4PortSetServiceEntry", "id": serviceid, "display_name": serviceid, "marked_for_delete": 'false', "_protection": "NOT_PROTECTED", "_revision": 0}]}
                    response = requests.patch(infourl,auth=self.nsxtauthvalues, verify=False, headers=headers,data=json.dumps(payload))                    
                if self.verbose:
                    if response.status_code == 200:
                        print("Created service ", serviceid)
                    else:
                        print("Failed to create service ", serviceid, ". Response:" , response.status_code, "\n")
            else:
                if self.verbose:
                    print("Service for ", serviceid, 'already exists, skipping.\n')

    def parsetiers(self):
        self.newsecgroups = []
        for line in glob.glob(os.path.join(self.rulefolder,"*FIRE*.xml")):
            dom = minidom.parse(line)
            sourcetier = dom.getElementsByTagName('sources')[0].getElementsByTagName('source')[0].getElementsByTagName('name')[0].firstChild.nodeValue
            destinationtier = dom.getElementsByTagName('destinations')[0].getElementsByTagName('destination')[0].getElementsByTagName('name')[0].firstChild.nodeValue
            self.newsecgroups.append(sourcetier.replace(" ", "-"))
            self.newsecgroups.append(destinationtier.replace(" ", "-"))
        self.newsecgroups = list(dict.fromkeys(self.newsecgroups))

    def createrules(self):
        if self.verbose:
            print("******* \n Creating rules. \n******* \n")
        for line in glob.glob(os.path.join(self.rulefolder,"*FIRE*.xml")):
            servicespatharray = []
            scope = []
            sourcepath = None
            destinationpath = None
            dom = minidom.parse(line)
            rulename =  dom.getElementsByTagName("name")[0].firstChild.nodeValue + "-vRNI-Import"
            rulename = rulename.replace('[', '').replace(']', '').replace(' ', '').replace('UFIREWALL_RULE-', '').replace('FIREWALL_RULE-', '')
            source =  dom.getElementsByTagName('sources')[0].getElementsByTagName('source')[0].getElementsByTagName('name')[0].firstChild.nodeValue.replace(" ", "-") + "-vRNI-Import-Tier" 
            for item in self.secgrouplist:
                if source == item.get('section id'):
                    sourcepath = [item.get('Path')]
                    scope.append(sourcepath[0])
            destination =  dom.getElementsByTagName('destinations')[0].getElementsByTagName('destination')[0].getElementsByTagName('name')[0].firstChild.nodeValue.replace(" ", "-") + "-vRNI-Import-Tier"
            for item in self.secgrouplist:
                if destination == item.get('section id'):
                    destinationpath = [item.get('Path')]
                    scope.append(destinationpath[0])
            services = [ x.getElementsByTagName('name')[0].firstChild.nodeValue for x in dom.getElementsByTagName('services')[0].getElementsByTagName('service') ]
            for item in services:
                service = item.split()
                service = service[0]
                serviceid = service + "-vRNI-Import"
                for item in self.serviceslookup:
                    if serviceid == item.get('id'):
                        servicespatharray.append(item.get('Path'))
            if self.vmc: 
                infourl = '%spolicy/api/v1/infra/domains/cgw/communication-maps/%s/communication-entries/%s' %(self.nsxpolicymanagerurl, self.applicationid, rulename)
                headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                payload = {"description": "comm entry", "display_name": rulename, "sequence_number": 1, "source_groups": sourcepath, "destination_groups": destinationpath, "services": servicespatharray, "action": "ALLOW", 'disabled': self.enablerules, "scope": scope}
                response = requests.put(infourl,headers=headers,data=json.dumps(payload))
            if self.nsxt:
                infourl = '%spolicy/api/v1/infra/domains/default/communication-maps/%s/communication-entries/%s' %(self.nsxturl, self.applicationid, rulename)
                headers = {'content-type': 'application/json'}
                payload = {"description": "comm entry", "display_name": rulename, "sequence_number": 1, "source_groups": sourcepath, "destination_groups": destinationpath, "services": servicespatharray, "action": "ALLOW", 'disabled': self.enablerules, "scope": scope}
                response = requests.put(infourl,auth=self.nsxtauthvalues, verify=False, headers=headers,data=json.dumps(payload))
            if self.verbose:
                if response.status_code == 200:
                    print("Created rule ", rulename, "\n")
                else:
                    print("Failed to create rule ", rulename, ". Response: ", response.status_code,"\n")

if __name__ == "__main__":
    try:
        VMCRuleImport().main()
    except KeyboardInterrupt:
        pass
        
        