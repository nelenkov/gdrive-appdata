#!/usr/bin/env python

import argparse
import httplib2
import os

import requests
import json
import time
import io
import sys
import hashlib

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
import googleapiclient

from xml.etree import ElementTree


DRIVE_APPDATA = 'https://www.googleapis.com/auth/drive.appdata'
DRIVE_FILE = 'https://www.googleapis.com/auth/drive.file'
SLEEP_TIME = 3 #secs

class GmsContext:
    GMS_SIG = '38918a453d07199354f8b19af05ec6562ced5788'
    GMS_PKG = 'com.google.android.gms'
    GMS_VERSION = 11055440
    GMS_UA = 'GoogleAuth/1.4 (bullhead MTC20F); gzip'

    def __init__(self, account, device_id, master_token):
        self.account = account
        self.device_id = device_id
        self.master_token = master_token
        
def get_gdrive_access_token(gms_ctx, app_id, app_sig):
    url = 'https://android.clients.google.com/auth'
    requestedService = 'oauth2:https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/drive.apps'

    d = {}
    d['androidId']= gms_ctx.device_id
    d['lang'] = 'en_US'
    d['google_play_services_version'] = GmsContext.GMS_VERSION
    d['sdk_version'] = 23
    d['device_country'] = 'us'
    d['is_called_from_account_manager'] = 1
    d['client_sig'] =  app_sig
    d['callerSig'] = GmsContext.GMS_SIG
    d['Email']  = gms_ctx.account
    d['has_permission'] = 1
    d['service'] = requestedService
    d['app'] =  app_id
    d['check_email'] = 1
    d['token_request_options'] = 'CAA4AQ=='
    d['system_partition'] = 1
    d['_opt_is_called_from_account_manager'] = 1
    d['callerPkg'] = GmsContext.GMS_PKG
    d['Token'] = gms_ctx.master_token

    headers = {}
    headers['Content-type'] = 'application/x-www-form-urlencoded'
    headers['Connection'] = 'close'

    r = requests.post(url, headers=headers, data=d)
    if r.status_code != 200:
        print 'Unexpected HTTP error, status code=%d: [%s]' % (r.status_code, r.text)
        return None

    r.raise_for_status()

    token = None
    lines = r.text.split('\n')
    for l in lines:
        if l.startswith('Auth'):
            token = l.split('=')[1].strip()
            break

    result  = {}
    result['access_token'] = token
    result['refresh_token'] = 'TOKEN'
    result['token_type'] = 'Bearer'
    result['expires_in'] = 360000
    result['id_token'] = 'TOKEN'
    result['created'] = int(time.time())

    #return json.dumps(result)
    return token

def get_master_token(account, password, device_id, target_package): 
    url = 'https://android.clients.google.com/auth'

    d = {}
    d['Email'] = account
    d['Passwd'] = password
    d['app'] = 'com.google.android.gms'
    d['client_sig'] = GmsContext.GMS_SIG
    d['google_play_services_version'] = GmsContext.GMS_VERSION
    d['androidId'] = device_id
    d['lang'] = 'en_US' 


    headers = {}
    headers['Content-type'] = 'application/x-www-form-urlencoded'
    headers['User-Agent'] =  GmsContext.GMS_UA
    headers['device'] = device_id
    headers['app'] = target_package
    headers['Connection'] = 'close'

    r = requests.post(url, headers=headers, data=d)
    r.raise_for_status()

    token = None
    lines = r.text.split('\n')
    for l in lines:
        if l.startswith('Token'):
            token = l.split('=')[1].strip()
            break

    return token;

def get_gdrive_credentials(gms_ctx, app_id, app_sig):
    gdrive_token = get_gdrive_access_token(gms_ctx, app_id, app_sig)
    print('GDrive token: %s' % gdrive_token)
    if gdrive_token is None:
        return None

    cred = client.AccessTokenCredentials(gdrive_token, 'Mozilla/5.0 compatible')
    cred.scopes.add(DRIVE_FILE)
    cred.scopes.add(DRIVE_APPDATA)
    
    return cred

def parse_packages(packages_file):
    result = {}    
    certs = {}
    with open(packages_file, 'r') as f:
        tree = ElementTree.parse(f) 
        for node in tree.findall('.//cert'):
            if 'key' in node.attrib:
                certs[node.attrib['index']] = node.attrib['key']

        for node in tree.findall('.//package'):
            if 'name' in node.attrib:
                package_name = node.attrib['name']
                cert_node = node.findall('.//sigs/cert')[0]
                cert_idx = cert_node.attrib['index']
                result[package_name] = hashlib.sha1(certs[cert_idx].decode('hex')).hexdigest()

    return result    

def main():
    device_id = '0000000000000000'

    help_msg = 'Fetches appdata/ from Google Drive. Specify either packages.xml or target package name and sig.'
    parser = argparse.ArgumentParser(description=help_msg)
    parser.add_argument('--packages-xml', help='packages.xml')
    parser.add_argument('--account', required=True, help='Google account')
    parser.add_argument('--password', required=True, help='Google password/app-specific password')
    parser.add_argument('--device-id', help='device ID')
    parser.add_argument('--target-package', help='Target package')
    parser.add_argument('--target-package-sig', help='SHA1 of target package signing cert')

    args = parser.parse_args()
    if args.packages_xml and args.target_package_sig:
        print 'Specify either --packages-xml or --target-package and --target-package-sig'
        sys.exit(2)
    if not args.packages_xml and (args.target_package and not args.target_package_sig) or (not args.target_package and args.target_package_sig):
        print 'Specify both --target-package and --target-package-sig if no --packages-xml'
        sys.exit(2)
        
    if args.device_id is not None:
        device_id = args.device_id
    target_package = args.target_package
    target_package_sig = args.target_package_sig
    packages_path = args.packages_xml

    print 'Using device ID=%s' % device_id
    print 'Using account: %s' % args.account

    master_token = get_master_token(args.account, args.password, device_id, target_package)
    print  'master token: %s' % master_token
    print

    gms_ctx = GmsContext(args.account, device_id, master_token)

    packages = {}
    # single package
    if target_package is not None and target_package_sig is not None:
       packages[target_package] = target_package_sig 
    else:
        packages = parse_packages(packages_path)

    for package in packages.keys():
        if target_package is not None and not target_package in package:
            continue

        cert_hash = packages[package]
        print 'Getting package [%s] with hash [%s]' % (package, cert_hash)
        credentials = get_gdrive_credentials(gms_ctx, package, cert_hash)
        if credentials is None:
            print('-' * 70)
            print
            continue

        http = credentials.authorize(httplib2.Http())
        service = discovery.build('drive', 'v3', http=http)

        results = []
        try:
            results = service.files().list(spaces='appDataFolder', 
                pageSize=100, fields="nextPageToken, files(id, name)").execute()
        except googleapiclient.errors.HttpError as e:
            print 'Error: %s' % e
            time.sleep(SLEEP_TIME)
            continue

        items = results.get('files', [])
        if not items:
            print 'No files found.'
            print
            time.sleep(SLEEP_TIME)
        else:
            backup_dir = 'appdata-%s-%s'  % (args.account.replace('@', '_'), str(int(time.time())))
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            print 'Saving in %s/' % backup_dir
            print

            package_dir = os.path.join(backup_dir, package)
            if not os.path.exists(package_dir):
                os.makedirs(package_dir)

            print('Files:')
            for item in items:
                print '%s: id=%s' % (item['name'], item['id'])
                name = '%s_%s' % (item['id'], item['name'])
                req = service.files().get_media(fileId=item['id'])
                path = os.path.join(package_dir, os.path.basename(name))
                with open(path, 'wb') as f:
                    fh = io.BytesIO()
                    downloader = googleapiclient.http.MediaIoBaseDownload(f, req)
                    done = False

                    try:
                        while done is False:
                            status, done = downloader.next_chunk()
                            print("Download %d %%." % int(status.progress() * 100))
                    except googleapiclient.errors.HttpError as e:
                        print 'Error: %s' % e
                        print
                        time.sleep(SLEEP_TIME)
                        continue
    print('-' * 70)
    print

if __name__ == '__main__':
    main()
