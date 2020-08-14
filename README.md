# Import vRNI Recommended Firewall Rules

This python script allows you to import the recommended firewall rules made by vRealize Network Insight, straight into VMware Cloud on AWS or an NSX-T Manager. Check out the different options below.

Export the recommended firewall rules from vRealize Network Insight in XML format (Security planner -> 3 dots in the top right -> Export as XML), then use this script to import.

By default, the imported rules wil be in a disabled state. There will be no impact on network traffic right away, until you start enabling the firewall rules (or pass the `--enablerules` parameter).

## Demo

Watch Trey walk through the export of the recommended firewall rules and then import into VMware Cloud on AWS, here: https://youtu.be/JYeZpWk9cbk

## Installation

Before you begin, some preresiquites:

- Connectivity to the internet from where script will be executed
- Connectivity to VMC SDDC over HTTPS (443)
- Connectivity to NSX-T Manager or VIP over HTTPS (443)

Then, clone the repository to your local system:

```shell
git clone https://github.com/vrealize-network-insight/vrni-rule-import-vmc-nsxt.git
```

Then install the Python module prerequisites with:

```shell
pip install -r requirements.txt
```

## Usage

```shell
# python vRNI_DFW_Rule_to_VMC_and_NSXT_Import.py --help
usage: vRNI_DFW_Rule_to_VMC_and_NSXT_Import.py [--help] [--orgid ORGID]
                                               [--rulefolder RULEFOLDER]
                                               [--sddcid SDDCID]
                                               [--refreshtoken REFRESHTOKEN]
                                               [--verbose] [--appname APPNAME]
                                               [--enablerules]
                                               [--nsxturl NSXTURL]
                                               [--nsxtuser NSXTUSER]

Export user created NSX-T Firewall rules and objects for a given VMC SDDC.

optional arguments:
  --help, -?            Print this usage message
  --orgid ORGID, -o ORGID
                        VMC organizational ID
  --rulefolder RULEFOLDER, -f RULEFOLDER
                        Folder directory location
  --sddcid SDDCID, -s SDDCID
                        SDDC ID
  --refreshtoken REFRESHTOKEN, -r REFRESHTOKEN
                        Generated API token
  --verbose, -v         Verbose output (print status messages)
  --appname APPNAME, -a APPNAME
                        Name of application for imported rules without spaces
  --enablerules         Creates enabled firewall rules. Default is disabled.
  --nsxturl NSXTURL, -n NSXTURL
                        URL of NSX-T Manager or VIP
  --nsxtuser NSXTUSER, -u NSXTUSER
                        NSX-T Username
```

## VMware Cloud on AWS

There are 2 output options for this script, one being VMware Cloud on AWS.

```shell
# python vRNI_DFW_Rule_to_VMC_and_NSXT_Import.py \
  --orgid "VMC organizational ID" \
  --rulefolder "Folder directory location with rules" \
  --sddcid "SDDC ID" \
  --refreshtoken "Generated CSP API token" \
  --appname "Name of application for imported rules without spaces" \
  --enablerules "Creates enabled firewall rules. Default is disabled."
```

A working example can be found in the [demo video](https://youtu.be/JYeZpWk9cbk).

### Getting an API Token

1. Login to https://console.cloud.vmware.com/
2. Click 'My Account' -> 'API Tokens' tab -> 'Generate Token' or Regenerate an existing token
3. Token must have NSX Cloud Admin service role under VMC on AWS service.
4. Copy token

### Getting the SDDC and Organisation ID

1. Login to https://console.cloud.vmware.com/
2. Select "VMware Cloud on AWS" under "My Services" -> Click desired SDDC -> Click Support
3. Copy Org ID  and SDDC ID

## VMware NSX-T

There are 2 output options for this script, one being NSX-T Manager.

```shell
# python vRNI_DFW_Rule_to_VMC_and_NSXT_Import.py \
  --rulefolder "Folder directory location with rules" \
  --appname "Name of application for imported rules without spaces" \
  --enablerules "Creates enabled firewall rules. Default is disabled." \
  --nsxturl "URL of NSX-T Manager or VIP" \
  --nsxtuser "NSX-T Username"
```

## Exporting Recommended Firewall Rules from vRNI

1. Log into vRNI
2. Search for "Plan security of application NAME" (changing NAME to the application name you would like to secure)
3. Select the three dots at the top right of the security donut diagram -> click "Export to XML"
4. Unzip the .zip file
5. Take note of the directory or folder location of the data center folder you will be importing rules for

## License

Network Insight Python SDK is licensed under GPL v2

Copyright © 2019 VMware, Inc. All Rights Reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 2, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License version 2 for more details.

You should have received a copy of the General Public License version 2 along with this program. If not, see https://www.gnu.org/licenses/gpl-2.0.html.

The full text of the General Public License 2.0 is provided in the COPYING file. Some files may be comprised of various open source software components, each of which has its own license that is located in the source code of the respective component.”