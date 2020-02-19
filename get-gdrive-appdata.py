#!/usr/bin/env python

import argparse
import httplib2
import os
import base64
import binascii

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

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

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
        print('Unexpected HTTP error, status code=%d: [%s]' % (r.status_code, r.text))
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

# from https://github.com/simon-weber/gpsoauth
"""The MIT License (MIT)

Copyright (c) 2015 Simon Weber

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

def bytes_to_long(s):
    return int.from_bytes(s, byteorder='big')

def long_to_bytes(lnum, padmultiple=1):
    """Packs the lnum (which must be convertable to a long) into a
       byte string 0 padded to a multiple of padmultiple bytes in size. 0
       means no padding whatsoever, so that packing 0 result in an empty
       string.  The resulting byte string is the big-endian two's
       complement representation of the passed in long."""

    # source: http://stackoverflow.com/a/14527004/1231454

    if lnum == 0:
        return b'\0' * padmultiple
    elif lnum < 0:
        raise ValueError("Can only convert non-negative numbers.")
    s = hex(lnum)[2:]
    s = s.rstrip('L')
    if len(s) & 1:
        s = '0' + s
    s = binascii.unhexlify(s)
    if (padmultiple != 1) and (padmultiple != 0):
        filled_so_far = len(s) % padmultiple
        if filled_so_far != 0:
            s = b'\0' * (padmultiple - filled_so_far) + s
    return s

def key_from_b64(b64_key):
    binaryKey = base64.b64decode(b64_key)

    i = bytes_to_long(binaryKey[:4])
    mod = bytes_to_long(binaryKey[4:4+i])

    j = bytes_to_long(binaryKey[i+4:i+4+4])
    exponent = bytes_to_long(binaryKey[i+8:i+8+j])

    key = RSA.construct((mod, exponent))

    return key


def key_to_struct(key):
    mod = long_to_bytes(key.n)
    exponent = long_to_bytes(key.e)

    return b'\x00\x00\x00\x80' + mod + b'\x00\x00\x00\x03' + exponent

def rsa_encrypt_auth(email, password, key):
    enc = bytearray(b'\x00')

    struct = key_to_struct(key)
    enc.extend(hashlib.sha1(struct).digest()[:4])

    cipher = PKCS1_OAEP.new(key)
    encrypted_login = cipher.encrypt((email + '\x00' + password).encode('utf-8'))

    enc.extend(encrypted_login)

    return base64.urlsafe_b64encode(enc)

def get_master_token(account, password, device_id, target_package): 
    url = 'https://android.clients.google.com/auth'
    
    b64_key_7_3_29 = (b"AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3"
                      b"iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK"
                      b"RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/"
                      b"6rmf5AAAAAwEAAQ==")

    android_key_7_3_29 = key_from_b64(b64_key_7_3_29)
    encpass = rsa_encrypt_auth(account, password, android_key_7_3_29)

    d = {}
    d['Email'] = account
    # raw password is no longer supported, returns 403
    #d['Passwd'] = password
    d['EncryptedPasswd'] = encpass
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
    print(('GDrive token: %s' % gdrive_token))
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
        print('Specify either --packages-xml or --target-package and --target-package-sig')
        sys.exit(2)
    if not args.packages_xml and (args.target_package and not args.target_package_sig) or (not args.target_package and args.target_package_sig):
        print('Specify both --target-package and --target-package-sig if no --packages-xml')
        sys.exit(2)
        
    if args.device_id is not None:
        device_id = args.device_id
    target_package = args.target_package
    target_package_sig = args.target_package_sig
    packages_path = args.packages_xml

    print('Using device ID=%s' % device_id)
    print('Using account: %s' % args.account)

    master_token = get_master_token(args.account, args.password, device_id, target_package)
    print('master token: %s' % master_token)
    print()

    gms_ctx = GmsContext(args.account, device_id, master_token)

    packages = {}
    # single package
    if target_package is not None and target_package_sig is not None:
       packages[target_package] = target_package_sig 
    else:
        packages = parse_packages(packages_path)

    for package in list(packages.keys()):
        if target_package is not None and not target_package in package:
            continue

        cert_hash = packages[package]
        print('Getting package [%s] with hash [%s]' % (package, cert_hash))
        credentials = get_gdrive_credentials(gms_ctx, package, cert_hash)
        if credentials is None:
            print(('-' * 70))
            print()
            continue

        http = credentials.authorize(httplib2.Http())
        service = discovery.build('drive', 'v3', http=http)

        results = []
        try:
            results = service.files().list(spaces='appDataFolder', 
                pageSize=100, fields="nextPageToken, files(id, name)").execute()
        except googleapiclient.errors.HttpError as e:
            print('Error: %s' % e)
            time.sleep(SLEEP_TIME)
            continue

        items = results.get('files', [])
        if not items:
            print('No files found.')
            print()
            time.sleep(SLEEP_TIME)
        else:
            backup_dir = 'appdata-%s-%s'  % (args.account.replace('@', '_'), str(int(time.time())))
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            print('Saving in %s/' % backup_dir)
            print()

            package_dir = os.path.join(backup_dir, package)
            if not os.path.exists(package_dir):
                os.makedirs(package_dir)

            print('Files:')
            for item in items:
                print('%s: id=%s' % (item['name'], item['id']))
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
                            print(("Download %d %%." % int(status.progress() * 100)))
                    except googleapiclient.errors.HttpError as e:
                        print('Error: %s' % e)
                        print()
                        time.sleep(SLEEP_TIME)
                        continue
    print(('-' * 70))
    print()

if __name__ == '__main__':
    main()
