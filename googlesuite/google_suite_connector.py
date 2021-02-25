#!/usr/bin/env python
# -*- coding: utf-8 -*-
from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
from argparse import SUPPRESS as AP_SUPPRESS
try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

import csv
import datetime
import httplib2
import logging
import os
import sys

script_name = os.path.basename(os.path.realpath(__file__))
script_directory = os.path.dirname(os.path.realpath(__file__))
lib_directory = os.path.realpath(os.path.join(script_directory, '../lib'))
if lib_directory not in sys.path:
    sys.path.append(lib_directory)

from o_common import ENCODING, OK_STATUS, rest_client
from o_common import logging_init, logging_level, get_dns
from o_common import arguments_check, fix_name, json_dump, load_namespace


log = logging.getLogger(__name__)

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/appsactivity-python-quickstart.json
SCOPES = 'https://www.googleapis.com/auth/activity ' \
         'https://www.googleapis.com/auth/drive.metadata.readonly ' \
         'https://www.googleapis.com/auth/admin.reports.audit.readonly ' \
         'https://www.googleapis.com/auth/admin.reports.usage.readonly ' \
         'https://www.googleapis.com/auth/urlshortener ' \
         'https://www.googleapis.com/auth/cloud-platform'

CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Google Suite Activity API Python Quickstart'
SCOPES_URL = SCOPES
TOKEN_COUNT = 1000

class ARCEO_VULN(object):
    # col in arceo_vulnerability
    connector_name    = ''
    connector_version = ''
    connector_id      = ''
    connector_type    = ''
    computer_id       = ''
    computer_name     = ''
    computer_dns      = ''
    computer_domain   = ''
    computer_ip       = ''   # inet
    computer_port     = 443  # integer
    computer_protocol = 'https'
    computer_service  = ''
    detected_ts       = ''  # timestamptz
    released_ts       = ''  # timestamptz
    name              = ''
    vendor            = 'Google G Suite'
    severity          = 'low'
    cvss              = 0.0  # float8
    cves              = ''
    links             = ''
    viruses           = ''
    is_error          = 0  # boolean DEFAULT false
    description       = ''

    # clear non-defaults
    def clear(self):
        self.connector_name    = ''
        self.connector_version = ''
        self.connector_id      = ''
        self.connector_type    = ''
        self.computer_id       = ''
        self.computer_name     = ''
        self.computer_dns      = ''
        self.computer_domain   = ''
        self.computer_ip       = ''  # inet
        self.computer_service  = ''
        self.detected_ts       = ''  # timestamptz
        self.released_ts       = ''
        self.name              = ''
        self.severity          = 'low'
        self.cvss              = 0.0  # float8
        self.cves              = ''
        self.links             = ''
        self.viruses           = ''
        self.is_error          = 0  # boolean DEFAULT false
        self.description       = ''


def get_credentials(secret_file):
    """Gets valid user credentials from storage.)

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir,'.credentials')

    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,'appsactivity-python-quickstart.json')

    store = Storage(credential_path)
    credentials = store.get()

    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(secret_file, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials


def write_results(output_base, db_vluns):
    output_json = './data/'+output_base + '.json'
    output_csv = './data/'+output_base + '.out'

    log.info('start writing output file: %s ...', [output_json, output_csv])

    with open(output_json, 'wb') as f:
        f.write(json_dump(db_vluns, sort_keys=False))

    with open(output_csv, 'wb') as f:
        if not db_vluns:
            return

        columns = db_vluns[0].keys()
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()

        for vlun in db_vluns:
            #    if isinstance(v, datetime):
            #        vlun[k] = v.isoformat()
            #    if isinstance(v, (list, tuple)):
            #        vlun[k] = ','.join(v)
            writer.writerow(vlun)

    log.info('finish writing output file: %s', [output_json,output_csv])


def map_out_to_arceo_vunlnerability(rows,v):
    rows.append({
            'connector_name':   v.connector_name.lower(),
            'connector_version':v.connector_version.lower(),
            'connector_id':     v.connector_id,
            'connector_type':   v.connector_type.lower(),
            'computer_id':      v.computer_id,
            'computer_name':    v.computer_name.lower(),
            'computer_dns':     v.computer_dns,
            'computer_domain':  v.computer_domain.lower(),
            'computer_ip':      v.computer_ip,    # inet
            'computer_port':    v.computer_port,  # integer
            'computer_protocol':v.computer_protocol.lower(),
            'computer_service': v.computer_service.lower(),
            'detected_ts':      v.detected_ts,    # timestamptz
            'released_ts':      v.released_ts,    # timestamptz
            'name':             v.name.lower(),
            'vendor':           v.vendor,
            'severity':         v.severity.lower(),
            'cvss':             v.cvss,      # float8
            'cves':             v.cves,
            'links':            v.links,
            'viruses':          v.viruses,
            'is_error':         v.is_error,  # boolean DEFAULT false
            'description':      v.description.lower(),
    })

def gsuite_adminreportsAPI(args):

    credentials = get_credentials('client_secret_activity.json')

    log.info('visit this OAuth consent URL to allow access: %s', credentials.token_info_uri)
    http = credentials.authorize(httplib2.Http())

    # Creates a Google Admin SDK Reports API service object
    log.info('Building an discovery service for reports_v1')
    service = discovery.build('admin', 'reports_v1', http=http)
    log.info('Built service object for: %s', service._baseUrl)

    # defaults values for col in arceo_vulnerability
    a = ARCEO_VULN()

    #  1 Request Admin reports. - for ref see - https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
    log.info('Fetch the last {} days of admin events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='admin',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])
    if not activities:
        log.info('NO GSuite admin events found.')
    else:
        log.info('*** Admin ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            a.connector_name    = activity['id']['applicationName']
            a.connector_name    = activity['id']['applicationName']
            a.connector_version = activity['actor']['profileId']
            a.connector_id      = activity['id']['uniqueQualifier']
            # The admin activity report's activity events types are:
            # APPLICATION_SETTINGS, CALENDAR_SETTINGS, CHAT_SETTINGS, CHROME OS_SETTINGS, CONTACTS_SETTINGS
            # DELEGATED_ADMIN, DOCS_SETTINGS, DOMAIN_SETTINGS, EMAIL_SETTINGS, GROUP_SETTINGS, LICENSES_SETTINGS
            # MOBILE_SETTINGS, ORG_SETTINGS, SECURITY_SETTINGS, SITES_SETTINGS, SYSTEM_SETTINGS, USER_SETTINGS
            a.connector_type    = activity['events'][0]['type']
            a.connector_type.lower
            a.computer_id       = activity['id']['customerId']
            a.computer_name     = activity['events'][0]['name']
            a.name              = activity['actor']['email']
            #  currently we/Google only support 1 event per activity
            for event in activity['events']:
                #log.info(event)
                event_name = event['name']

                try:  # we don't always have 'parameters'
                    for parameter in event['parameters']:
                        # log.info(parameter)
                        if 'ADD_NICKNAME' in event_name:
                            # if 'EMAIL' in parameter['name']:
                            #    description = description + parameter['value'] + ' created '
                            if 'NICKNAME' in parameter['name']:
                                a.description = a.description + ' nickname:' + parameter['value']
                        elif 'DOMAIN_NAME' in parameter['name']:
                            a.computer_domain = parameter['value']
                        elif 'SERVICE_NAME' in parameter['name']:
                            a.computer_service = parameter['value']
                        elif 'PLAY_FOR_WORK_MDM_VENDOR_NAME' in parameter['name']:
                            a.computer_service = parameter['value']
                        else:
                            a.description = a.description + parameter['name'] + ':' + parameter['value'] + ','

                except:
                    iparams = 0;

            if a.description == '':
                a.description = event_name

            try: # ipAddress can be missing for some event_types, like Google Mobile Management, that's ok.
                a.computer_ip       = activity['ipAddress']  # inet
                if  a.computer_id != '':
                    a.computer_dns = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            if a.computer_service == '':
                a.computer_service  = event_name

            a.detected_ts = activity['id']['time']  # timestamptz
            a.released_ts = a.detected_ts  # same as detected_ts

            if 'security_settings' in a.connector_type:
                a.severity      = 'mid'
            else:
                a.severity      = 'low'

            # a.links             =  a.name

            map_out_to_arceo_vunlnerability(rows,a)

        write_results('admin', rows)

    # 2 Request Login reports
    log.info('Getting the last {} login events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='login',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])

    if not activities:
        log.info('No logins found.')
    else:
        log.info('*** Logins ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            event_name = activity['events'][0]['name']
            a.connector_name    = event_name
            a.connector_version = activity['actor']['profileId']
            a.connector_id      = activity['id']['uniqueQualifier']
            a.connector_type    = activity['events'][0]['type']
            a.connector_type.lower
            a.computer_id       = activity['id']['customerId']
            a.name              = activity['actor']['email']

            if 'login_failure' in event_name:
                is_error = 1
                # Map the severity based on the type of login_failure that occurred.
                if len(activity['events'][0]['parameters']) > 1:
                    event_value = activity['events'][0]['parameters'][1]['value']
                    log.info(event_value)
                    if 'login_failure_access_code_disallowed' in event_value:  # - The user does not have permission to login to the service.'
                        a.severity = 'mid'
                        a.description = 'access_code_disallowed'
                    elif 'login_failure_account_disabled' in event_value:  # - The user's account is disabled.'
                        a.severity = 'high'
                        a.description = 'account_disabled'
                    elif 'login_failure_invalid_password' in event_value:  # - The user's password was invalid.'
                        a.severity = 'mid'
                        a.description = 'invalid_password'
                    elif 'login_failure_invalid_second_factor' in event_value:  # - If two-factor authentication is enabled, the user supplied an invalid second form of identification. '
                        a.severity = 'mid'
                        a.description = 'invalid_second_factor'
                    elif 'login_failure_missing_second_factor' in event_value:  # - If two-factor authentication is enabled, the user did not supply a second authentication factor such as a one-time password. '
                        a.severity = 'mid'
                        a.description = 'missing_second_factor'
                    elif 'login_failure_unknown' in event_value:  # - The reason for the login failure is not known.'
                        a.severity = 'high'
                        a.description = 'failure_unknown'
                    else:
                        a.severity = 'high'  # - We end up here only when new event_values are added by Google.
                        a.specal_note = '- Undetermined login failure -  MAINTENANCE: Check Google API for new failure values.'
                        a.description = a.specal_note + ' ' + a.description + ' Severity:'+a.severity
                        log.error(a.description)
            elif 'login_challenge' in event_name:
                log.info(event_name)
                if len(activity['events'][0]['parameters']) > 1:
                    login_challenge_status = activity['events'][0]['parameters'][1]['value']
                    if ('Challenge Passed') in login_challenge_status:
                        a.is_error = 0
                        a.severity = 'low'
                        a.description = login_challenge_status
                    elif 'Challenge Failed' in login_challenge_status:
                        a.is_error = 1
                        a.severity = 'mid'
                        a.description = login_challenge_status
                    else:
                        a.is_error = 1
                        a.severity = 'high'
                        a.description = 'Challenge Failed unknown status'
                # login_challenge_status
                # Whether the login challenge succeeded or failed, represented as "Challenge Passed." and "Challenge Failed." respectively.
                # An empty string indicates an unknown status.
            else:
                is_error = 0
                if len(activity['events'][0]['parameters']) > 1:
                    a.is_suspicious = activity['events'][0]['parameters'][1]['value']
                    # The login attempt had some unusual characteristics, for example the user logged in from an unfamiliar IP address.
                    if a.is_suspicious:
                        a.is_suspicious = 1.0
                        a.suspicious = 'Suspicious'
                        a.severity = 'mid'
                    else:
                        a.is_suspicious = 0.0
                        a.suspicious = 'Normal'
                        a.severity = 'low'
                else:
                    a.is_suspicious = 0.0
                    a.suspicious = 'Normal'
                    a.severity = 'low'

                a.description = a.suspicious + ' login activity'

            if a.description == '':
                a.description = event_name

            try: # ipAddress can be missing for some event_types
                a.computer_ip       = activity['ipAddress']  # inet
                if  a.computer_id != '':
                    a.computer_dns      = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            a.detected_ts    = activity['id']['time']  # timestamptz
            a.released_ts    = a.detected_ts  # same as detected_t
            a.links          = a.name

            map_out_to_arceo_vunlnerability(rows,a)

        write_results('login',rows)


    # 3 Request GDrive reports
    log.info('Getting the last {} GDrive events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='drive',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])

    if not activities:
        log.info('No GDrive events found.')
    else:
        log.info('*** GDrive ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            a.connector_name    = activity['id']['applicationName']
            a.connector_type    = activity['events'][0]['name']
            a.connector_name    = activity['events'][0]['name']
            a.connector_version = activity['actor']['profileId']
            a.connector_id      = activity['id']['uniqueQualifier']
            a.connector_type    = activity['events'][0]['type']
            a.connector_type.lower
            a.computer_id       = activity['id']['customerId']

            #  currently we/Google only support 1 event per activity
            for event in activity['events']:
                # log.info(event)
                event_name = event['name']

                try:  # we don't always have 'parameters'
                    for parameter in event['parameters']:
                        # log.info(parameter)
                        if 'DOMAIN_NAME' in parameter['name']:
                            computer_domain = parameter['value']
                        elif 'SERVICE_NAME' in parameter['name']:
                            a.computer_service = parameter['value']
                        else:
                            a.description = a.description + parameter['name'] + ':' + parameter['value'] + ','

                except:
                    iparams = 0;

            a.computer_service = activity['kind']

            try: # ipAddress can be missing for some event_types
                a.computer_ip       = activity['ipAddress']  # inet
                if  a.computer_id != '':
                    a.computer_dns      = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            a.detected_ts = activity['id']['time']  # timestamptz
            a.released_ts = a.detected_ts  # same as detected_ts

            a.links = activity['actor']['email']

            if a.description == '':
                a.description = event_name

            map_out_to_arceo_vunlnerability(rows,a)

        write_results('drive', rows)

    # 4 Request Group reports
    log.info('Getting the last {} groups events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='groups',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])

    if not activities:
        log.info('No groups events found.')
    else:
        log.info('*** Groups ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            a.connector_name    = activity['events'][0]['name']
            a.connector_version = activity['actor']['profileId']
            a.connector_id      = activity['id']['uniqueQualifier']
            a.connector_type    = activity['events'][0]['type']
            a.connector_type.lower
            a.computer_id       = activity['id']['customerId']

            #  currently we/Google only support 1 event per activity
            for event in activity['events']:
                #log.info(event)
                event_name = event['name']

                try:  # we don't always have 'parameters'
                    for parameter in event['parameters']:
                        #log.info(parameter)
                        if 'DOMAIN_NAME' in parameter['name']:
                            a.computer_domain = parameter['value']
                        elif 'SERVICE_NAME' in parameter['name']:
                            a.computer_service = parameter['value']
                        else:
                            a.description = a.description + parameter['name'] + ':' + parameter['value'] + ','

                except:
                    iparams = 0;

            if a.computer_service == '':
                a.computer_service = activity['kind']

            try: # ipAddress can be missing for some event_types
                a.computer_ip      = activity['ipAddress'] #inet
                if  a.computer_id != '':
                    a.computer_dns = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            a.detected_ts = activity['id']['time']  # timestamptz
            a.released_ts = a.detected_ts #same as detected_ts
            a.name = activity['actor']['email']
            #  vendor =

            if a.description == '':
                a.description = event_name

            map_out_to_arceo_vunlnerability(rows,a)

        write_results('groups', rows)

    # 5 Request Mobile reports
    log.info('Getting the last {} mobile events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='mobile',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])

    if not activities:
        log.info('No mobile events found.')
    else:
        log.info('*** Mobile ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            a.connector_name    = activity['events'][0]['name']
            a.connector_version = activity['actor']['profileId']  # perhaps NOT this here
            a.connector_id      = activity['id']['uniqueQualifier']
            a.connector_type    = activity['events'][0]['type']  # 'DOMAIN_SETTINGS'/'SECURITY_SETTINGS'...
            a.computer_id       = activity['id']['customerId']
            a.computer_service  = activity['kind']
            a.detected_ts       = activity['id']['time']  # timestamptz
            a.released_ts       = a.detected_ts  # timestamptz
            a.name              = activity['actor']['email']
            a.description       = activity['events'][0]['name']

            try: # ipAddress can be missing for some event_types
                a.computer_ip   = activity['ipAddress'] #inet
                if  a.computer_id != '':
                    a.computer_dns = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            map_out_to_arceo_vunlnerability(rows, a)

        write_results('mobile', rows)

    #6 Request OAuth Token reports
    log.info('Getting the last {} token events'.format(args.token_count))
    results = service.activities().list(userKey='all', applicationName='token',
                                        maxResults=args.token_count).execute()
    activities = results.get('items', [])

    if not activities:
        log.info('No OAuth token events found.')
    else:
        log.info('*** OAuth Tokens ***')
        rows = []

        for activity in activities:
            log.info(activity)
            a.clear()
            a.connector_name    = activity['id']['applicationName']
            a.connector_type    = activity['id']['applicationName'] # 'token'...
            a.connector_version = activity['actor']['profileId']
            a.connector_id      = activity['id']['uniqueQualifier']
            a.connector_type.lower
            a.computer_id       = activity['id']['customerId']
            a.computer_service  = activity['kind']

            try: # ipAddress can be missing for some event_types
                a.computer_ip      = activity['ipAddress'] #inet
                if  a.computer_id != '':
                    a.computer_dns = get_dns(a.computer_ip)
            except:
                log.info('Info ipAddress = %s',a.computer_ip)

            a.detected_ts = activity['id']['time']  # timestamptz
            a.released_ts = a.detected_ts #same as detected_ts
            a.name = activity['actor']['email']
            #  currently we/Google only support 1 event per activity
            for event in activity['events']:
                #log.info(event)
                #event_name = event['name']

                try:  # we don't always have 'parameters'
                    for parameter in event['parameters']:
                        #log.info(parameter)
                        if 'app_name' in parameter['name']:
                            app_name = parameter['value']
                        if 'DOMAIN_NAME' in parameter['name']:
                            a.computer_domain = parameter['value']
                        elif 'SERVICE_NAME' in parameter['name']:
                            a.computer_service = parameter['value']
                        else:
                            a.description = a.description + parameter['name'] + ':' + parameter['value'] + ','

                except:
                    iparams = 0;

            if app_name != '':
                a.description = app_name

            if 'authorize' in a.connector_name:
                a.severity = 'low'

            if a.description == '':
               a.description = activity['events'][0]['name']

            map_out_to_arceo_vunlnerability(rows, a)

        write_results('tokens', rows)


def gsuite_activityAPI():
    """Shows basic usage of the G Suite Activity API."""
    credentials = get_credentials(CLIENT_SECRET_FILE)
    http = credentials.authorize(httplib2.Http())

    """ create an service object with  build() construction, is specific to the given API """
    service = discovery.build('appsactivity', 'v1', http=http)

    """Creates a G Suite Activity API service object and outputs the recent activity in your Google Drive."""
    results = service.activities().list(source='drive.google.com',
                                        drive_ancestorId='root', pageSize=10).execute()
    # defaults values for col in arceo_vulnerability
    a = ARCEO_VULN()

    activities = results.get('activities', [])
    if not activities:
        log.info('No activity.')
    else:
        log.info('Recent GDrive activity:')
        rows = []

        for activity in activities:
            a.clear()

            event = activity['combinedEvent']
            user = event.get('user', None)
            target = event.get('target', None)
            if user == None or target == None:
                continue

            try:
                a.connector_name   = 'GDrive'
                a.connector_type   = event['primaryEventType']
                a.connector_type.lower()
                a.connector_id     = target['id']
                a.computer_name    = target['name'] # is fname
                a.computer_service = target['mimeType']
                a.name             = user['name']
                a.computer_id      = user['permissionId']
                time               = datetime.datetime.fromtimestamp(int(event['eventTimeMillis'])/1000)
                a.detected_ts      = time
                a.released_ts      = a.detected_ts  # same as detect ed_ts

                log.info('{0}: {1}, {2}, {3} ({4})'.format(time, user['name'],
                    event['primaryEventType'], target['name'], target['mimeType']))

            except:
                iparams = 0;

            if a.description == '':
                a.description = a.name + ' ' + a.connector_type + ' ' + a.computer_name + '(' + a.computer_service + ')'

            map_out_to_arceo_vunlnerability(rows, a)

        write_results('gdrive', rows)


def parse_arguments(argv):
    parser = ArgumentParser(description='Collects Metrics from Google Google-Suite.',
      formatter_class= ArgumentDefaultsHelpFormatter, add_help=False)
    parser.add_argument('-?', '--help',            action='help',           help='Show Help Message And Exit', default=AP_SUPPRESS)
    parser.add_argument('-v', '--verbose',         action='store_true',     help='Enable Debug Logging')
    parser.add_argument('-s', '--scopes-url',      default=SCOPES_URL,      help='SCOPES URL')
    parser.add_argument('-t', '--token-count',     default=TOKEN_COUNT,     help='Event Count')
    parser.add_argument('-k', '--key',                                      help='Application Key')
    namespace = load_namespace(parser, os.environ.get('PREFIX', 'GSUITE'))
    args = parser.parse_args(argv, namespace)

    #arguments_check(args, ['domin', 'key'])

    return args


def main(argv=None):
    logging_init(script_name, 'google-suite', facility='local4', stream=sys.stdout)
    args = parse_arguments(argv)
    logging_level(args)

    gsuite_adminreportsAPI(args)
    gsuite_activityAPI()

    return 0


# Starting point
if __name__ == '__main__':
    sys.exit(main())