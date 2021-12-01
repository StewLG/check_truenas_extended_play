#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2015 Goran Tornqvist
# Extended by Stewart Loving-Gibbard 2020, 2021
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


import argparse
import json
import sys
import string
import urllib3
import requests
import logging

class Startup(object):

    def __init__(self, hostname, user, secret, use_ssl, verify_cert, ignore_dismissed_alerts, debug_logging, zpool_name, wfree, cfree):
        self._hostname = hostname
        self._user = user
        self._secret = secret
        self._use_ssl = use_ssl
        self._verify_cert = verify_cert
        self._ignore_dismissed_alerts = ignore_dismissed_alerts
        self._debug_logging = debug_logging
        self._zpool_name = zpool_name
        self._wfree = wfree
        self._cfree = cfree
 
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
 

    # This was causing me trouble, but we may need to bring something like it back
    # if we need to POST.
    
    # def request(self, resource, method='get', data=none):
        # if data is none:
            # data = ''
        # try:
            # request_url = '%s/%s/' % (self._base_url, resource)
            # logging.debug('request_url: %s', request_url)
            
            # # we get annoying warning text output from the urllib3 library if we fail to do this
            # if (not self._verify_cert):
                # urllib3.disable_warnings(urllib3.exceptions.insecurerequestwarning);
            
            # r = requests.request(
                # method,
                # request_url,
                # data=json.dumps(data),
                # headers={'content-type': "application/json"},
                # auth=(self._user, self._secret),
                # verify=self._verify_cert,
            # )
            
            # r.raise_for_status()
        # except:
            # print ('unknown - request failed - error when contacting truenas server: ' + str(sys.exc_info()) )
            # sys.exit(3)
 
        # if r.ok:
            # try:
                # return r.json()
            # except:
                # print ('unknown - json failed to parse - error when contacting truenas server: ' + str(sys.exc_info()))
                # sys.exit(3)
 
    def get_request(self, resource):
        try:
            request_url = '%s/%s/' % (self._base_url, resource)
            logging.debug('request_url: %s', request_url)
            
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
            
            r = requests.get(request_url, 
                            auth=auth,
                            headers=headers,
                            verify=self._verify_cert)
            logging.debug('request response: %s', r.text)

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
 
    def check_alerts(self):
        alerts = self.get_request('alert/list')
        
        logging.debug('alerts: %s', alerts)
        
        warn=0
        crit=0
        critial_messages = ''
        warning_messages = ''
        try:
            for alert in alerts:
                # Skip over dismissed alerts if that's what user requested 
                if (self._ignore_dismissed_alerts and alert['dismissed'] == True):
                    continue
                if alert['level'] == 'CRITICAL':
                    crit = crit + 1
                    critial_messages = critial_messages + '- (C) ' + alert['formatted'].replace('\n', '. ') + ' '
                elif alert['level'] == 'WARNING':
                    warn = warn + 1
                    warning_messages = warning_messages + '- (W) ' + alert['formatted'].replace('\n', '. ') + ' '
        except:
            print ('UNKNOWN - check_alerts() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL ' + critial_messages + warning_messages)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING ' + warning_messages)
            sys.exit(1)
        else:
            print ('OK - No problem alerts')
            sys.exit(0)
 
    def check_zpool(self):
        pool_results = self.get_request('pool')

        logging.debug('pool_results: %s', pool_results)
        
        warn=0
        crit=0
        critial_messages = ''
        warning_messages = ''
        zpools_examined = ''
        actual_zpool_count = 0
        all_pool_names = ''
        perfdata= ';|'
        
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
                    # 'label'=value[UOM];[warn];[crit];[min];[max]
                    mnt = pool["path"]
                    maxBytes = pool["topology"]["data"][0]["stats"]["size"]
                    usedBytes = pool["topology"]["data"][0]["stats"]["allocated"]
                    usedMegaBytes = usedBytes / 1024 / 1024
                    warnPercent = self._wfree
                    critPercent = self._cfree
                    warnBytes = maxBytes / 100 * warnPercent
                    critBytes = maxBytes / 100 * critPercent
                    if (maxBytes > 0): 
                        usagePercent = usedBytes / maxBytes * 100
                    else: 
                        usagePercent=100
                    if (usagePercent >= critPercent):
                        crit += 1
                        critial_messages += "- Pool " + pool_name + " usage " + f'{usagePercent:3.1f}' + "% exceeds critical value of " + str(critPercent) +"%"
                    else:
                        if (usagePercent >= warnPercent):
                            warn += 1
                            warning_messages += "- Pool " + pool_name + " usage " + f'{usagePercent:3.1f}' + "% exceeds warning value " + str(warnPercent) +"%"

                    logging.debug("Pool %s, Max, Used, Percent: %d %d %d", pool_name, maxBytes, usedBytes, usagePercent)
                    perfdata += " " + mnt + "=" + str(usedMegaBytes) + "MB;" + str(warnBytes/1024/1024) + ";" + str(critBytes/1024/1024) + ";0;" + str(maxBytes/1024/1024)
                    if (pool_status != 'ONLINE'):
                        crit = crit + 1
                        critial_messages = critial_messages + '- (C) ZPool ' + pool_name + 'is ' + pool_status
        except:
            print ('UNKNOWN - check_zpool() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        # There were no Zpools on the system, and we were looking for all of them
        if (zpools_examined == '' and actual_zpool_count == 0 and looking_for_all_pools):
            zpools_examined = '(None - No Zpools found)'
            
        # There were no Zpools matching a specific name on the system
        if (zpools_examined == '' and actual_zpool_count > 0 and not looking_for_all_pools and crit == 0):
            crit = crit + 1
            critial_messages = '- No Zpools found matching {} out of {} pools ({})'.format(self._zpool_name, actual_zpool_count, all_pool_names)

        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL ' + critial_messages + warning_messages + perfdata)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING ' + warning_messages + perfdata)
            sys.exit(1)
        else:
            print ('OK - No problem Zpools. Zpools examined: ' + zpools_examined + perfdata)
            sys.exit(0)
 
    def handle_requested_alert_type(self, alert_type):
        if alert_type == 'alerts':
            self.check_alerts()
        elif alert_type == 'repl':
            self.check_repl()
            
        elif alert_type == 'zpool':
            self.check_zpool()

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

check_truenas_script_version = '1.1'

def main():
    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks a TrueNAS/FreeNAS server using the 2.0 API. Version ' + check_truenas_script_version)
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--user', required=False, type=str, help='Username, only root works, if not specified: use API Key')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password or API Key')
    parser.add_argument('-t', '--type', required=True, type=str, help='Type of check, either alerts, zpool, or repl')
    parser.add_argument('-pn', '--zpoolname', required=False, type=str, default='all', help='For check type zpool, the name of zpool to check. Optional; defaults to all zpools.')
    parser.add_argument('-ns', '--no-ssl', required=False, action='store_true', help='Disable SSL (use HTTP); default is to use SSL (use HTTPS)')
    parser.add_argument('-nv', '--no-verify-cert', required=False, action='store_true', help='Do not verify the server SSL cert; default is to verify the SSL cert')
    parser.add_argument('-ig', '--ignore-dismissed-alerts', required=False, action='store_true', help='Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as relevant')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')
    parser.add_argument('-c', '--cfree', required=False, type=int, default=90, help='Critical storage capacity free threshold.')
    parser.add_argument('-w', '--wfree', required=False, type=int, default=80, help='Warning storage capacity free threshold.')
 
    # if no arguments, print out help
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
 
    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    use_ssl = not args.no_ssl
    verify_ssl_cert=not args.no_verify_cert
 
    startup = Startup(args.hostname, args.user, args.passwd, use_ssl, verify_ssl_cert, args.ignore_dismissed_alerts, args.debug, args.zpoolname, args.wfree, args.cfree)
 
    startup.handle_requested_alert_type(args.type)
 
if __name__ == '__main__':
    main()
    
