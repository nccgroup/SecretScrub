# Released as open source by NCC Group Plc - https://www.nccgroup.com/
#
# Developed by:
#     Andrew Kisliakov (andrew.kisliakov@nccgroup.com)
#
# Project link: https://www.github.com/nccgroup/secretscrub/
#
# Released under AGPL-3.0. See LICENSE for more information.

import base64
import csv
from enum import Enum
import json
import logging
import os
import pyzipper
import tempfile

class SecretScrubReportEncryption(Enum):

    NONE = 'none'
    ZIP_AES256 = 'zip-aes256'

    def __str__(self):
        return self.value
    
    def __repr__(self):
        return str(self)
        
    @staticmethod
    def argparse(s):
        return next((v for v in SecretScrubReportEncryption if v.value == s), s)

class SecretScrubReport:

    def __init__(self, path, encryption):
        self.f = None
        self.csv = None
        self.path = path
        self.tmp_path = None
        self.encryption = encryption
        self.encryption_key = None
        if path:
            self.open()

    def prompt_encryption_key(self):
        if not self.path:
            return None
        if self.encryption != SecretScrubReportEncryption.NONE:
            return f'The final report file will be encrypted using the "{self.encryption.value}" method. Please supply a password'
        return None
    
    def set_encryption_key(self, key : str):
        self.encryption_key = key

    def open(self):
        if self.path:
            self.f = tempfile.NamedTemporaryFile(mode='w', newline='', encoding='utf-8', delete=False)
            self.tmp_path = self.f.name
            self.csv = csv.DictWriter(self.f, fieldnames=['File Name','Directory','Commit','Start Line','Tool','Content','Status','Message'])
            self.csv.writeheader()

    def close(self):
        if self.csv:
            self.csv = None
        if self.f:
            self.f.close()
            self.f = None
        if self.path and self.tmp_path:
            if self.encryption == SecretScrubReportEncryption.ZIP_AES256:
                zip_path = f'{self.path}.zip'
                with pyzipper.AESZipFile(zip_path, mode='w') as z:
                    pswd = self.encryption_key
                    if isinstance(pswd, str):
                        pswd = pswd.encode('utf-8')
                    z.setpassword(pswd)
                    z.setencryption(pyzipper.WZ_AES)
                    z.write(self.tmp_path, arcname=os.path.basename(self.path))
                    os.unlink(self.tmp_path)
                    self.path = zip_path
            else:
                os.rename(self.tmp_path, self.path)

    def log_result(self, sarif_result, content_list, status, message):
        if not self.csv:
            return

        try:
            loc = sarif_result.locations[0]
            (file_dir, file_name) = os.path.split(os.path.normpath(loc.artifact_path).replace('\\','/'))
            rowdata = {
                'File Name' : file_name,
                'Directory' : file_dir,
                'Commit' : sarif_result.commit_sha,
                'Start Line' : loc.start_line + 1,
                'Tool' : sarif_result.tool_name,
                'Content' : self.encode_content_list(content_list),
                'Status' : status,
                'Message' : message
            }
            self.csv.writerow(rowdata)
        except Exception as e:
            logging.warning(f'Cannot write report entry: {e}')
            return
    
    def log_file_result(self, file_path, status, message):
        if not self.csv:
            return

        try:
            (file_dir, file_name) = os.path.split(os.path.normpath(file_path).replace('\\','/'))
            rowdata = {
                'File Name' : file_name,
                'Directory' : file_dir,
                'Commit' : None,
                'Start Line' : None,
                'Tool' : None,
                'Content' : None,
                'Status' : status,
                'Message' : message
            }
            self.csv.writerow(rowdata)
        except Exception as e:
            logging.warning(f'Cannot write report entry: {e}')
            return

    def encode_content_list(self, content_list):
        if not content_list:
            return ''
        
        encoded_content_list = list((base64.b64encode(c).decode('utf-8') if isinstance(c, bytes) else c) for c in content_list)
        
        # If 1 element, output a quoted string (using JSON escaping format), otherwise output a JSON list.
        return json.dumps(encoded_content_list[0] if len(encoded_content_list) == 1 else encoded_content_list)
    