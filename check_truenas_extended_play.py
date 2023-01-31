#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2015 Goran Tornqvist
# Extended by Stewart Loving-Gibbard 2020, 2021, 2022, 2023
# Additional help from Folke Ashberg 2021
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

# Attempt to require minimum version of Python
#
# NOTE: This will NOT work much of the time, and instead you'll get a cryptic 
# error because this script won't compile at all in earlier versions of Python.
#
# For example, several users are seeing this and not understanding it:
#
# curie# ./check_truenas_extended_play.py
#  File "./check_truenas_extended_play.py", line 48
#    ZpoolName: str
#
# This is dying because of the user of Dataclass in earlier versions of Python that
# don't recognize it. Dataclass was introduced in Python 3.7.
# 
# So, this is both the least and most we can do without having wrappers or shell scripts
# or batch files, none of which is going to make this script any easier to use.
#
# Sorry I can't do more without deliberately avoding language features!
#
# -- SLG 3/1/2022
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

import argparse
import json
import string
import urllib3
import requests
import logging
from dataclasses import dataclass
from enum import Enum

class RequestTypeEnum(Enum):
    GET_REQUEST = 1
    POST_REQUEST = 2

@dataclass
class ZpoolCapacity:
    ZpoolName: str
    ZpoolAvailableBytes: int
    TotalUsedBytesForAllDatasets: int
  

class Startup(object):

    def __init__(self, hostname, user, secret, use_ssl, verify_cert, ignore_dismissed_alerts, debug_logging, zpool_name, zpool_warn, zpool_critical, show_zpool_perfdata):
        self._hostname = hostname
        self._user = user
        self._secret = secret
        self._use_ssl = use_ssl
        self._verify_cert = verify_cert
        self._ignore_dismissed_alerts = ignore_dismissed_alerts
        self._debug_logging = debug_logging
        self._zpool_name = zpool_name
        self._wfree = zpool_warn
        self._cfree = zpool_critical
        self._show_zpool_perfdata = show_zpool_perfdata
 
        http_request_header = 'https' if use_ssl else 'http'
 
        self._base_url = ('%s://%s/api/v2.0' % (http_request_header, hostname) )
        
        self.setup_logging()
        self.log_startup_information()

    def log_startup_information(self):
        logging.debug('')
        logging.debug('hostname: %s', self._hostname)
        logging.debug('use_ssl: %s', self._use_ssl)
        logging.debug('verify_cert: %s', self._verify_cert)
        logging.debug('base_url: %s', self._base_url)
        logging.debug('zpool_name: %s', self._zpool_name)
        logging.debug('wfree: %d', self._wfree)
        logging.debug('cfree: %d', self._cfree)
        logging.debug('')
 

    # Do a GET or POST request
    def do_request(self, resource, requestType, optionalPayload):
        try:
            request_url = '%s/%s/' % (self._base_url, resource)
            logging.debug('request_url: %s', request_url)
            logging.debug('requestType: ' + repr(requestType))
            #logging.debug('optionalPayloadAsJson:' + optionalPayloadAsJson)

            # We assume that all incoming payloads are JSON. 
            optionalPayloadAsJson = json.dumps(optionalPayload)
            logging.debug('optionalPayloadAsJson:' + optionalPayloadAsJson)
            
            # We get annoying warning text output from the urllib3 library if we fail to do this
            if (not self._verify_cert):
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            auth=False
            headers={}

            # If username provided, try to authenticate with username/password combo
            if (self._user): 
                auth=(self._user, self._secret)
            # Otherwise, use API key
            else: 
                headers={'Authorization': 'Bearer ' + self._secret}
            
            # GET Request
            if (requestType is RequestTypeEnum.GET_REQUEST):
                if (optionalPayload):
                    r = requests.get(request_url, 
                                    auth=auth,
                                    headers=headers,
                                    data=optionalPayloadAsJson,
                                    verify=self._verify_cert)
                else:
                    r = requests.get(request_url, 
                                    auth=auth,
                                    headers=headers,
                                    verify=self._verify_cert)                    
                logging.debug('GET request response: %s', r.text)
            # POST Request                
            elif (requestType is RequestTypeEnum.POST_REQUEST):
                if (optionalPayload):                
                    r = requests.post(request_url, 
                                    auth=auth,
                                    headers=headers,
                                    data=optionalPayloadAsJson,
                                    verify=self._verify_cert)
                else:
                    r = requests.post(request_url, 
                                    auth=auth,
                                    headers=headers,
                                    verify=self._verify_cert)
                logging.debug('POST request response: %s', r.text)
            else:
                print ('UNKNOWN - request failed - Unknown RequestType: ' + requestType)
                sys.exit(3)

            r.raise_for_status()
        except:
            print ('UNKNOWN - request failed - Error when contacting TrueNAS server: ' + str(sys.exc_info()) )
            sys.exit(3)
 
        if r.ok:
            try:
                return r.json()
            except:
                print ('UNKNOWN - json failed to parse - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
                sys.exit(3)

    # GET request
    def get_request(self, resource):
        return self.do_request(resource, RequestTypeEnum.GET_REQUEST, None)

    # GET request with payload
    def get_request_with_payload(self, resource, optionalPayload):
        return self.do_request(resource, RequestTypeEnum.GET_REQUEST, optionalPayload)

    # POST request
    def post_request(self, resource):
        return self.do_request(resource, RequestTypeEnum.POST_REQUEST, None)

    # POST request with payload
    def post_request_with_payload(self, resource, optionalPayload):
        return self.do_request(resource, RequestTypeEnum.POST_REQUEST, optionalPayload)

    def check_repl(self):
        repls = self.get_request('replication')
        errors=0
        msg=''
        replications_examined = ''

        try:
            for repl in repls:
                logging.debug('Replication response: %s', repl)
                repl_name = repl['name']
                logging.debug('Replication name: %s', repl_name)
                repl_state_obj = repl['state']
                logging.debug('Replication state object: %s', repl_state_obj)
                repl_state_code = repl_state_obj['state']
                logging.debug('Replication state code: %s', repl_state_code)

                replications_examined = replications_examined + ' ' + repl_name + ': ' + repl_state_code
                
                repl_was_not_success = (repl_state_code != 'FINISHED')
                repl_not_running = (repl_state_code != 'RUNNING')
                if (repl_was_not_success and repl_not_running):
                    errors = errors + 1
                    msg = msg + repl_name + ': ' + repl_state_code
        except:
            print ('UNKNOWN - check_repl() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
 
        if errors > 0:
            print ('WARNING - There are ' + str(errors) + ' replication errors [' + msg.strip() + ']. Go to Storage > Replication Tasks > View Replication Tasks in TrueNAS for more details.')
            sys.exit(1)
        else:
            print ('OK - No replication errors. Replications examined: ' + replications_examined)
            sys.exit(0)


    def check_update(self):
        updateCheckResult = self.post_request('update/check_available')
        warnings=0
        errors=0
        msg=''
        needsUpdateOrOtherPossibleIssue=False
        updateCheckResultString=''

        # From https://www.truenas.com/docs/api/rest.html#api-Update-updateCheckAvailablePost
        updateCheckResultDict = {
            'UNAVAILABLE': 'no update available',
            'AVAILABLE': 'an update is available',
            'REBOOT_REQUIRED': 'an update has already been applied',
            'HA_UNAVAILABLE': 'HA is non-functional'
        }

        try:
            logging.debug('Update check result: %s', updateCheckResult)
            
            updateCheckResultString = updateCheckResult['status']
            # Despite that it sounds error-y, 'UNAVAILABLE' is actually the normal everything-is-ok state.
            needsUpdateOrOtherPossibleIssue = (updateCheckResultString != 'UNAVAILABLE')

        except:
            print ('UNKNOWN - check_update() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
 
        if needsUpdateOrOtherPossibleIssue:
            if (updateCheckResultString in updateCheckResultDict):
                print ('WARNING - Update Status: ' + updateCheckResultString + ' (' + updateCheckResultDict[updateCheckResultString] + '). Update may be required. Go to TrueNAS Dashboard -> System -> Update to check for newer version.')
            # Unfamiliar status we've never seen before    
            else:
                print ('WARNING - Unknown Update Status: ' + updateCheckResultString + '. Update may be required. Go to TrueNAS Dashboard -> System -> Update to check for newer version.')
            sys.exit(1)
        else:
            print ('OK - Update Status: ' + updateCheckResultString + ' (' + updateCheckResultDict[updateCheckResultString] + ')')
            sys.exit(0)


    def check_alerts(self):
        alerts = self.get_request('alert/list')
        
        logging.debug('alerts: %s', alerts)
        
        warn=0
        crit=0
        critical_messages = ''
        warning_messages = ''
        try:
            for alert in alerts:
                # Skip over dismissed alerts if that's what user requested 
                if (self._ignore_dismissed_alerts and alert['dismissed'] == True):
                    continue
                if alert['level'] == 'CRITICAL':
                    crit = crit + 1
                    critical_messages = critical_messages + '- (C) ' + alert['formatted'].replace('\n', '. ') + ' '
                elif alert['level'] == 'WARNING':
                    warn = warn + 1
                    warning_messages = warning_messages + '- (W) ' + alert['formatted'].replace('\n', '. ') + ' '
        except:
            print ('UNKNOWN - check_alerts() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL ' + critical_messages + warning_messages)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING ' + warning_messages)
            sys.exit(1)
        else:
            print ('OK - No problem alerts')
            sys.exit(0)
 
    def check_zpool(self):
        pool_results = self.get_request('pool')

        #logging.debug('pool_results: %s', pool_results)
        
        warn=0
        crit=0
        critical_messages = ''
        warning_messages = ''
        zpools_examined = ''
        actual_zpool_count = 0
        all_pool_names = ''
        
        looking_for_all_pools = self._zpool_name.lower() == 'all'
        
        try:
            for pool in pool_results:

                actual_zpool_count += 1
                pool_name = pool['name']
                pool_status = pool['status']
                
                all_pool_names += pool_name + ' '
                
                logging.debug('Checking zpool for relevancy: %s with status %s', pool_name, pool_status)
                
                # Either match all pools, or only the requested pool
                if (looking_for_all_pools or self._zpool_name == pool_name):
                    logging.debug('Relevant Zpool found: %s with status %s', pool_name, pool_status)
                    zpools_examined = zpools_examined + ' ' + pool_name
                    logging.debug('zpools_examined: %s', zpools_examined)
                    if (pool_status != 'ONLINE'):
                        crit = crit + 1
                        critical_messages = critical_messages + '- (C) ZPool ' + pool_name + 'is ' + pool_status
        except:
            print ('UNKNOWN - check_zpool() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        # There were no Zpools on the system, and we were looking for all of them
        if (zpools_examined == '' and actual_zpool_count == 0 and looking_for_all_pools):
            zpools_examined = '(None - No Zpools found)'
            
        # There were no Zpools matching a specific name on the system
        if (zpools_examined == '' and actual_zpool_count > 0 and not looking_for_all_pools and crit == 0):
            crit = crit + 1
            critical_messages = '- No Zpools found matching {} out of {} pools ({})'.format(self._zpool_name, actual_zpool_count, all_pool_names)

        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL ' + critical_messages + warning_messages)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING ' + warning_messages)
            sys.exit(1)
        else:
            print ('OK - No problem Zpools. Zpools examined: ' + zpools_examined)
            sys.exit(0)

    

    def check_zpool_capacity(self):
        # As far as I can tell, we unfortunately have to look at the datasets to get a usable
        # capacity value. There are numbers on a pool's output, but I can't make sense of them - 
        # when added up and made into percentages, they are very off (10-20%) for complex multiply
        # vdev'd zpools, and don't agree with the TrueNAS GUI.

        # Instead, this dataset call gives us a hierarchical view of datasets, rather than the default flattened view. This means
        # we can just look at root-level datasets coming back from this request, and then add up their used 
        # capacity for a given zpool. This total will be the real used total for the Zpool. Again, this is
        # circuitous and complicated, and I am only doing it because I think it's the only way with the current
        # API. If you know better, please let me know!
        #
        # -- SLG 12/04/2021


        BYTES_IN_MEGABYTE = 1024 * 1024;

        logging.debug('check_zpool_capacity')

        warnZpoolCapacityPercent = self._wfree
        critZpoolCapacityPercent = self._cfree

        datasetPayload = {
            'query-options': {
                'extra': {
                    'flat': False
                }
            },
             'query-filters': []   
        }     
        dataset_results = self.get_request_with_payload('pool/dataset', datasetPayload)

        warn=0
        crit=0
        critical_messages = ''
        warning_messages = ''
        zpools_examined_with_no_issues = ''
        root_level_datasets_examined = ''
        root_level_dataset_count = 0
        all_root_level_dataset_names = ''
        perfdata = ''
        if (self._show_zpool_perfdata):
            perfdata= ';|'
        
        # We allow filtering on pool name here
        looking_for_all_pools = self._zpool_name.lower() == 'all'

        # Build a dict / array thingy and add to it as we proceed...
        zpoolNameToCapacityDict = {}
        
        try:
            # Go through all the datasets, and sum up values for the zpools we are interested in
            for dataset in dataset_results:
                root_level_dataset_count += 1
                dataset_name = dataset['name']
                dataset_pool_name = dataset['pool']
                
                all_root_level_dataset_names += dataset_name + ' '
                
                logging.debug('Checking root-level dataset for relevancy: dataset %s from pool %s', dataset_name, dataset_pool_name)
                
                # Either match all datasets, from any pool, or only datasets from the requested pool
                if (looking_for_all_pools or self._zpool_name == dataset_pool_name):
                    logging.debug('Relevant root-level dataset found: dataset %s from pool %s', dataset_name, dataset_pool_name)
                    root_level_datasets_examined = root_level_datasets_examined + ' ' + dataset_name
                    logging.debug('root_level_datasets_examined: %s', root_level_datasets_examined)

                    dataset_used_bytes = dataset['used']['parsed']
                    dataset_available_bytes = dataset['available']['parsed']

                    logging.debug('dataset_used_bytes: %d', dataset_used_bytes)
                    logging.debug('dataset_available_bytes: %d', dataset_available_bytes)

                    # We haven't seen this Zpool before, starting new summary record about it
                    if (not dataset_pool_name in zpoolNameToCapacityDict):
                        # dataset_available_bytes is the same for any dataset in a zpool, so we can just use the first
                        # one encountered. It will be the same value for all the relevant data sets, since they are all
                        # in the same Zpool with the same amount of available space
                        newZpoolCapacity = ZpoolCapacity(dataset_pool_name, dataset_available_bytes, dataset_used_bytes)
                        zpoolNameToCapacityDict[dataset_pool_name] = newZpoolCapacity
                    # Otherwise we've seen it before, update our count of used bytes
                    else:
                        zpoolNameToCapacityDict[dataset_pool_name].TotalUsedBytesForAllDatasets += dataset_used_bytes
                    logging.debug('currentZpoolCapacity: ' + str(zpoolNameToCapacityDict[dataset_pool_name]))


            # So now we have summary data on all the Zpools we care about. Go through each of them 
            # and see if any are above warning/critical percentages.
            for currentZpoolCapacity in zpoolNameToCapacityDict.values():
                zpoolTotalBytes = currentZpoolCapacity.ZpoolAvailableBytes + currentZpoolCapacity.TotalUsedBytesForAllDatasets
                usedPercentage = (currentZpoolCapacity.TotalUsedBytesForAllDatasets / zpoolTotalBytes ) * 100;
                usagePercentDisplayString = f'{usedPercentage:3.1f}'
                
                logging.debug('Warning capacity: ' + str(warnZpoolCapacityPercent) + '%' + ' Critical capacity: ' + str(critZpoolCapacityPercent) + '%')                 
                logging.debug('ZPool ' + str(currentZpoolCapacity.ZpoolName) + ' usedPercentage: ' + usagePercentDisplayString + '%')  
                
                # Add warning/critical errors for the current ZPool summary being checked, if needed
                if (usedPercentage >= critZpoolCapacityPercent):
                    crit += 1
                    critical_messages += " - Pool " + currentZpoolCapacity.ZpoolName + " usage " + usagePercentDisplayString + "% exceeds critical value of " + str(critZpoolCapacityPercent) + "%"                        
                elif (usedPercentage >= warnZpoolCapacityPercent):
                    warn += 1
                    warning_messages += " - Pool " + currentZpoolCapacity.ZpoolName + " usage " + usagePercentDisplayString + "% exceeds warning value of " + str(warnZpoolCapacityPercent) + "%"
                else:
                    # Don't add dashes to start, only to additions
                    if (len(zpools_examined_with_no_issues) > 0):
                        zpools_examined_with_no_issues += ' - '
                    zpools_examined_with_no_issues += currentZpoolCapacity.ZpoolName + ' (' + usagePercentDisplayString + '% used)'                    

                # Add perfdata if user requested it
                if (self._show_zpool_perfdata):
                    usedMegaBytes = currentZpoolCapacity.TotalUsedBytesForAllDatasets / BYTES_IN_MEGABYTE
                    usedMegabytesString = f'{usedMegaBytes:3.2f}'                    

                    warningBytes = zpoolTotalBytes * (warnZpoolCapacityPercent / 100)
                    warningMegabytes = warningBytes / BYTES_IN_MEGABYTE
                    warningMegabytesString = f'{warningMegabytes:3.2f}'

                    criticalBytes = zpoolTotalBytes * (critZpoolCapacityPercent / 100)
                    criticalMegabytes = criticalBytes / BYTES_IN_MEGABYTE
                    criticalMegabytesString = f'{criticalMegabytes:3.2f}'

                    totalMegabytes = zpoolTotalBytes / BYTES_IN_MEGABYTE
                    totalMegabytesString = f'{totalMegabytes:3.2f}' 

                    logging.debug('usedMegabytesString: ' + usedMegabytesString)  
                    logging.debug('warningMegabytesString: ' + warningMegabytesString)  
                    logging.debug('criticalMegabytesString: ' + criticalMegabytesString)                      
                    logging.debug('totalMegabytesString: ' + totalMegabytesString)  

                    perfdata += " " + currentZpoolCapacity.ZpoolName + "=" + usedMegabytesString + "MB;" + warningMegabytesString + ";" + criticalMegabytesString + ";0;" + totalMegabytesString                                

        except:
            print ('UNKNOWN - check_zpool() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        # There were no datasets on the system, and we were looking for datasets from any pool
        if (root_level_datasets_examined == '' and root_level_dataset_count == 0 and looking_for_all_pools):
            root_level_datasets_examined = '(No Datasets found)'
            
        # There were no datasets matching the requested specific pool name on the system
        if (root_level_datasets_examined == '' and root_level_dataset_count > 0 and not looking_for_all_pools and crit == 0):
            crit = crit + 1
            critical_messages = '- No datasets found matching ZPool {} out of {} root level datasets ({})'.format(self._zpool_name, root_level_dataset_count, all_root_level_dataset_names)

        # If we have zpools with no issues to show in a warning/error, we want a leading dash in front of it.
        # Otherwise, no dash.
        error_or_warning_dividing_dash = ''
        if (len(zpools_examined_with_no_issues) > 0):
            error_or_warning_dividing_dash = ' - '
            logging.debug('Yes there is a dividing dash:' + error_or_warning_dividing_dash)

        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL' + critical_messages + warning_messages + error_or_warning_dividing_dash + zpools_examined_with_no_issues + perfdata)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING' + warning_messages + error_or_warning_dividing_dash + zpools_examined_with_no_issues + perfdata)
            sys.exit(1)
        else:
            print ('OK - No Zpool capacity issues. ZPools examined: ' + zpools_examined_with_no_issues + ' - Root level datasets examined:' + root_level_datasets_examined + perfdata)
            sys.exit(0)



    def handle_requested_alert_type(self, alert_type):
        if alert_type == 'alerts':
            self.check_alerts()
        elif alert_type == 'repl':
            self.check_repl()
        elif alert_type == 'update':
            self.check_update()
        elif alert_type == 'zpool':
            self.check_zpool()
        elif alert_type == 'zpool_capacity':
            self.check_zpool_capacity()
        else:
            print ("Unknown type: " + alert_type)
            sys.exit(3)

    def setup_logging(self):
        logger = logging.getLogger()
        
        if (self._debug_logging):
            #print('Trying to set logging level debug')
            logger.setLevel(logging.DEBUG)
        else:
            #print('Should be setting no logging level at all')
            logger.setLevel(logging.CRITICAL)

check_truenas_script_version = '1.42'

default_zpool_warning_percent = 80
default_zool_critical_percent = 90

def main():
    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks a TrueNAS/FreeNAS server using the 2.0 API. Version ' + check_truenas_script_version)
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--user', required=False, type=str, help='Username, only root works, if not specified: use API Key')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password or API Key')
    parser.add_argument('-t', '--type', required=True, type=str, help='Type of check, either alerts, zpool, zpool_capacity, repl, or update')
    parser.add_argument('-pn', '--zpoolname', required=False, type=str, default='all', help='For check type zpool, the name of zpool to check. Optional; defaults to all zpools.')
    parser.add_argument('-ns', '--no-ssl', required=False, action='store_true', help='Disable SSL (use HTTP); default is to use SSL (use HTTPS)')
    parser.add_argument('-nv', '--no-verify-cert', required=False, action='store_true', help='Do not verify the server SSL cert; default is to verify the SSL cert')
    parser.add_argument('-ig', '--ignore-dismissed-alerts', required=False, action='store_true', help='Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as relevant')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')
    parser.add_argument('-zw', '--zpool-warn', required=False, type=int, default=default_zpool_warning_percent, help='ZPool warning storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zpool_warning_percent) + '%%. Used with zpool_capacity check.')    
    parser.add_argument('-zc', '--zpool-critical', required=False, type=int, default=default_zool_critical_percent, help='ZPool critical storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zool_critical_percent) +'%%. Used with zpool_capacity check.')
    parser.add_argument('-zp', '--zpool-perfdata', required=False, action='store_true', help='Add Zpool capacity perf data to output. Used with zpool_capacity check.')    
    
    # if no arguments, print out help
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
 
    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    use_ssl = not args.no_ssl
    verify_ssl_cert = not args.no_verify_cert
 
    startup = Startup(args.hostname, args.user, args.passwd, use_ssl, verify_ssl_cert, args.ignore_dismissed_alerts, args.debug, args.zpoolname, args.zpool_warn, args.zpool_critical, args.zpool_perfdata)
 
    startup.handle_requested_alert_type(args.type)
 
if __name__ == '__main__':
    main()
    
