import argparse
import base64
import json
import logging
import os
import regex
import sys

from .bindetect_types import *

FILETYPE_ASN1 = 'asn1'

FILENAME_PATTERNS = {
    r'\.bks$': None,               # BouncyCastle KeyStore, proprietary format
    r'\.der$': [Asn1Processor],    # DER encoded certificate, binary ASN.1 file
    r'\.jks$': [Asn1Processor],    # Java KeyStore, binary ASN.1 file
    r'\.key$': [Asn1Processor],    # Private key file, binary ASN.1 file
    r'\.keystore$': None,          # Generic KeyStore, undetermined format
    r'\.(pfx|p12)': None,          # PKCS#12 format
    r'\.ppk$': None                # Putty private key
}

def main():
    global args
    args = parse_args()
    bin_detect(args.srcdir, args.out)

def parse_args():
    parser = argparse.ArgumentParser(prog = __file__)
    parser.add_argument('-s', '--srcdir', required=True)
    parser.add_argument('-o', '--out')
    args = parser.parse_args()

    if not args.srcdir:
        args.srcdir = os.getcwd()

    return args

def bin_detect(src_dir, out_path):
    sarif_findings = list(process_dir(src_dir))
    sarif_rules = build_rules()
    sarif_tool = build_sarif_tool(sarif_rules)
    sarif_doc = build_sarif_doc(sarif_tool, sarif_findings)
    out_file = sys.stdout if out_path else open(out_path, 'w')
    try:
        if out_path:
            out_file = open(out_path, 'w')
            json.dump(sarif_doc, out_file, indent=2)
    finally:
        if out_path:
            out_file.close()

def process_dir(src_dir):
    logging.debug('Beginning Binary Detection...')
    for root, _, files in os.walk(src_dir):
        for filename in files:
            try:
                with open(os.path.join(root, filename), 'rb') as f:
                    file_data = f.read()
            except IOError as e:
                logging.error(f'Error reading file {filename} : {e}')
                continue

            for filename_pattern in FILENAME_PATTERNS:
                if not regex.search(filename_pattern, filename):
                    continue

                secret_segments = handle_file(filename_pattern, file_data)
                rel_path = get_path_relative_to(os.path.join(root, filename), src_dir)
                for secret_segment in secret_segments:
                    sarif_result = {
                        'ruleId' : f'bin_{filename_pattern}',
                        'message' : {
                            'text' : f'bin_{filename_pattern} has detected secret for file {rel_path}.'
                        },
                        'locations' : [
                            {
                                'physicalLocation' : {
                                    'artifactLocation' : {
                                        'uri' : rel_path
                                    },
                                    'region' : {
                                        'byteOffset': secret_segment[0],
                                        'byteLength': secret_segment[1],
                                        'snippet' : {
                                            'binary' : base64.b64encode(file_data[secret_segment[0]:secret_segment[1]]).decode('utf-8')
                                        }
                                    }
                                }
                            }
                        ]
                    }

                    yield sarif_result
                
def get_path_relative_to(path, dir):
    try:
        relpath = os.path.relpath(path, dir)
        if relpath.startswith('..' + os.pathsep):
            return None
        return relpath.replace('\\', '/')
    except:
        return None

def handle_file(filename_pattern, file_data):
    processors = FILENAME_PATTERNS[filename_pattern]

    if processors is None:
        return [(0, len(file_data))]
    else:
        secret_segments = []
        for processor in processors:
            processed_segments = processor().process(file_data)
            if processed_segments:
                secret_segments = secret_segments + processed_segments
        return secret_segments

def build_rules():
    sarif_rules = []
    for filename_pattern in FILENAME_PATTERNS:
        tags = []
        tags.append('secret')
        sarif_rules.append({
            'id' : f'bin_{filename_pattern}',
            'name' : f"Binary File Name Matching '{filename_pattern}'",
            'properties' : {
                'tags' : tags
            }
        })
    return sarif_rules

def build_sarif_tool(sarif_rules):
    tool_def = {
        'driver' : {
            'fullName' : 'BinDetect',
            'informationUri' : 'https://git.pentest.ngs/andrew.kisliakov/secretscrub/',
            'name' : 'BinDetect',
            'rules' : sarif_rules
        }
    }
    return tool_def

def build_sarif_doc(sarif_tool, sarif_results):
    sarif_doc = {
        'version' : '2.1.0',
        '$schema' : 'https://json.schemastore.org/sarif-2.1.0-rtm.5.json',
        'runs' : [
            {
                'tool' : sarif_tool,
                'results' : list(sarif_results)
            }
        ]
    }
    return sarif_doc

if __name__ == '__main__':
    main()