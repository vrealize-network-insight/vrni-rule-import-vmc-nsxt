#################################################################################
#                                                                               #
#  The purpose of this script is to import firewall rules exported by vRNI to   #
#  a SDDC deployed in VMware VMC on AWS.                                        #
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
from xml.dom import minidom
from xml.dom.minidom import parse, parseString

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

        if not self.orgid:
            self.orgid = input('Please provide organization ID:  ')
        if not self.sddcid:
            self.sddcid = input('Please provide SDDC ID:  ')
        if not self.refreshtoken:
            self.refreshtoken = input('Please provide API Token:  ')
        if not self.rulefolder:
            self.rulefolder = input('Please input rule folder location: ')
        if not self.applicationname:
            self.applicationname = input('Please input name of application for imported rules without spaces:  ')

    ### Functions run order ###
        self.gettoken()
        self.getproxyurls()
        self.getfirewallsectionids()
        self.createfirewallrulesection()
        self.getsecuritygroups()
        self.parsetiers()
        self.createsecuritygroups()
        self.getsecuritygroups()    
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
        infourl = '%s/policy/api/v1/infra/domains/cgw/communication-maps' %(self.srevproxyurl)
        headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
        payload = {}
        response = requests.get(infourl, headers=headers, data=payload)
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
        infourl = '%s/policy/api/v1/infra/domains/cgw/groups' %(self.srevproxyurl)
        headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
        payload = {}
        response = requests.get(infourl, headers=headers, data=payload)
        d = json.loads(response.text)
        self.secgrouplist = []
        self.secgroupids = []
        for item in d.get("results"):
            if item.get('id').startswith('vRNI-Import'):
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
        infourl = '%s/policy/api/v1/infra/services' %(self.srevproxyurl)
        headers = {'csp-auth-token': self.token, 'content-type': 'application/json'}
        payload = {}
        response = requests.get(infourl, headers=headers, data=payload)
        d = json.loads(response.text)
        existingservices = d["results"]
        self.serviceslookup =[]
        self.existingservices =[]
        for rule in existingservices:
            if rule.get('id').startswith("vRNI-Import-"):
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
            print("******* \n Creating security groups. Please note: Created security groups are not populated with members. You will need to add Virtual Machines and IPs to created security groups as necessary. \n******* \n")
        for tier in self.newsecgroups:
            tiername = "vRNI-Import-Tier-" + tier
            if tiername in self.secgroupids:
                print("Security group for ", tiername, " already created.  Skipping. \n")
                continue
            else:
                infourl = '%spolicy/api/v1/infra/domains/cgw/groups/%s' %(self.nsxpolicymanagerurl, tiername)
                headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                payload = {"resource_type": "Group", "id": tiername , "display_name": tiername, "_protection": "NOT_PROTECTED", "_revision": 0}
                response = requests.patch(infourl,headers=headers,data=json.dumps(payload))
                if self.verbose:
                    if response.status_code != 200:
                        print("Unable to create new security group " + tiername + ". Response: ", response.status_code, "\n")
                    else:
                        print("Security Group Created: " + tiername, "\n")

    def createfirewallrulesection(self):
        self.applicationid = 'vRNIImport-' + self.applicationname
        if self.applicationid in self.communicationmaps:
            if self.verbose:
                print("Application communication map already exists: ", self.applicationid , ", skipping to create groups \n")
        else:
            infourl = '%spolicy/api/v1/infra/domains/cgw/communication-maps/%s' %(self.nsxpolicymanagerurl, self.applicationid)
            headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
            payload = {"precedence": "1", "category": "Application", "resource_type": "CommunicationMap", "id": self.applicationid, "display_name": self.applicationname}
            response = requests.put(infourl,headers=headers,data=json.dumps(payload))
            fwrulesection = json.loads(response.text)
            self.sectionid = fwrulesection["id"]
            if self.verbose:
                if response.status_code != 200:
                    print("Unable to create new communication map. Response: ", response.status_code, "\n")
                else:
                    print("Created policy section: ", self.sectionid, "\n")

    def creatservicesdefinitions(self):
        self.services = []
        for line in glob.glob(os.path.join(self.rulefolder,"*FIRE*.xml")):
            dom = minidom.parse(line)
            services = [ x.getElementsByTagName('name')[0].firstChild.nodeValue for x in dom.getElementsByTagName('services')[0].getElementsByTagName('service') ]
            self.services.extend(services)
        self.services = list(dict.fromkeys(self.services))
        for service in self.services:
            service = service.split()
            service = service[0]
            serviceid = "vRNI-Import-" + service
            if serviceid not in self.existingservices:
                splitservice = service.split('-', 2)
                infourl = '%spolicy/api/v1/infra/services/%s' %(self.nsxpolicymanagerurl, serviceid)
                headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
                payload = {"is_default": "true", "service_entries": [{"l4_protocol": splitservice[1], "source_ports": [], "destination_ports": [splitservice[2]], "resource_type": "L4PortSetServiceEntry", "id": serviceid, "display_name": serviceid, "marked_for_delete": 'false', "_protection": "NOT_PROTECTED", "_revision": 0}]}
                response = requests.patch(infourl,headers=headers,data=json.dumps(payload))
                if response.status_code == 200:
                    print("Created service ", serviceid)
                else:
                    print("Failed to create service ", serviceid, ". Response:" , response.status_code, "\n")
            else:
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
        for line in glob.glob(os.path.join(self.rulefolder,"*FIRE*.xml")):
            servicespatharray = []
            sourcepath = None
            destinationpath = None
            dom = minidom.parse(line)
            rulename = "vRNI-Import-" + dom.getElementsByTagName("name")[0].firstChild.nodeValue
            rulename = rulename.replace('[', '').replace(']', '').replace(' ', '')
            source = "vRNI-Import-Tier-" + dom.getElementsByTagName('sources')[0].getElementsByTagName('source')[0].getElementsByTagName('name')[0].firstChild.nodeValue.replace(" ", "-")  
            for item in self.secgrouplist:
                if source == item.get('section id'):
                    sourcepath = [item.get('Path')]
            destination = "vRNI-Import-Tier-" + dom.getElementsByTagName('destinations')[0].getElementsByTagName('destination')[0].getElementsByTagName('name')[0].firstChild.nodeValue.replace(" ", "-")
            for item in self.secgrouplist:
                if destination == item.get('section id'):
                    destinationpath = [item.get('Path')]
            services = [ x.getElementsByTagName('name')[0].firstChild.nodeValue for x in dom.getElementsByTagName('services')[0].getElementsByTagName('service') ]
            for item in services:
                service = item.split()
                service = service[0]
                serviceid = "vRNI-Import-" + service
                for item in self.serviceslookup:
                    if serviceid == item.get('id'):
                        servicespatharray.append(item.get('Path'))
            infourl = '%spolicy/api/v1/infra/domains/cgw/communication-maps/%s/communication-entries/%s' %(self.nsxpolicymanagerurl, self.applicationid, rulename)
            headers = {'Authorization': str('Bearer ' + self.token), 'content-type': 'application/json'}
            payload = {"description": "comm entry", "display_name": rulename, "sequence_number": 1, "source_groups": sourcepath, "destination_groups": destinationpath, "services": servicespatharray, "action": "ALLOW", 'disabled': self.enablerules}
            response = requests.put(infourl,headers=headers,data=json.dumps(payload))
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
