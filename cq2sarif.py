# Released as open source by NCC Group Plc - https://www.nccgroup.com/
#
# Developed by:
#     Andrew Kisliakov (andrew.kisliakov@nccgroup.com)
#
# Project link: https://www.github.com/nccgroup/secretscrub/
#
# Released under AGPL-3.0. See LICENSE for more information.

import argparse
import ast
import glob
import json
import logging
import os
import regex
import sys

def main():
    global args
    args = parse_args()
    cq_to_sarif(args.cq, args.srcdir, args.input, args.out)

def cq_to_sarif(cq_path, src_dir, cq_results, out_path):
    cq = Cq(cq_path)
    sarif_rules = build_rules(cq)
    sarif_tool = build_sarif_tool(sarif_rules)
    sarif_findings = process_sarif_findings(sarif_rules, src_dir, cq_results)
    sarif_doc = build_sarif_doc(sarif_tool, sarif_findings)
    out_file = open(out_path, 'w') if out_path else sys.stdout
    try:
        json.dump(sarif_doc, out_file, indent=2)
    finally:
        if out_path:
            out_file.close()

def parse_args():
    parser = argparse.ArgumentParser(prog = __file__)
    parser.add_argument('-c', '--cq', required=True)
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-s', '--srcdir', required=True)
    parser.add_argument('-o', '--out')
    args = parser.parse_args()

    if not args.srcdir:
        args.srcdir = os.getcwd()

    return args

def build_rules(cq):
    sarif_rules = []
    for line_regex_check in cq.line_regex_checks:
        tags = []
        if line_regex_check.startswith('cred_'):
            tags.append('secret')
        sarif_rules.append({
            'id' : line_regex_check,
            'name' : line_regex_check.replace('-',' ').replace('_',' '),
            'shortDescription' : {
                'text' : cq.line_regex_checks[line_regex_check]
            },
            'properties' : {
                'tags' : tags
            }
        })
    return sarif_rules

def build_sarif_tool(sarif_rules):
    tool_def = {
        'driver' : {
            'fullName' : 'cq',
            'informationUri' : 'https://github.com/chris-anley/cq',
            'name' : 'cq',
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

def process_sarif_findings(sarif_rules, src_dir, cq_results):
    for path in glob.glob(os.path.join(cq_results,'*.txt')):
        rule_id = os.path.basename(path)[:-len('.txt')]
        if not rule_id in [r['id'] for r in sarif_rules]:
            logging.info(f"Regular expression definition '{rule_id}' not found in CQ library")
            continue

        logging.info(f'Processing {rule_id}...')
        with open(path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            (src_path, src_line, src_text) = parse_cq_output_line(line)
            rel_path = get_path_relative_to(src_path, src_dir)
            if not rel_path:
                continue

            sarif_result = {
                'ruleId' : rule_id,
                'message' : {
                    'text' : f'{rule_id} has detected secret for file {rel_path}.'
                },
                'locations' : [
                    {
                        'physicalLocation' : {
                            'artifactLocation' : {
                                'uri' : rel_path
                            },
                            'region' : {
                                'startLine' : src_line,
                                'endLine' : src_line,
                                'snippet' : {
                                    'text' : src_text.rstrip('\r\n')
                                }
                            }
                        }
                    }
                ]
            }

            yield sarif_result

WINDOWS_PATH_REGEX = regex.compile(r'^[a-zA-Z]:[/\\]')
def parse_cq_output_line(line):
    split = line.split(':')
    if WINDOWS_PATH_REGEX.match(line):
        split = [(split[0] + ':' + split[1])] + split[2:]
    return (split[0], int(split[1]), split[2])

def get_path_relative_to(path, dir):
    try:
        relpath = os.path.relpath(path, dir)
        if relpath.startswith('..' + os.pathsep):
            return None
        return relpath.replace('\\', '/')
    except:
        return None

# Represents the cq.py file that was used to generate the cq output being processed. This contains
# a list of regular expressions that are parsed out from the file using Python's built-in AST analyzer.
class Cq:
    def __init__(self, path):
        cqpy_path = os.path.join(path, 'cq.py') if not path.endswith('.py') else path
        with open(cqpy_path, "r") as cqpy_file:
            cqpy_ast = ast.parse(cqpy_file.read())

        analyzer = CqRegexAnalyzer()
        analyzer.visit(cqpy_ast)
        self.line_regex_checks = analyzer.line_regex_checks


class CqRegexAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.line_regex_checks = {}

    def visit_Assign(self, node):
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == 'LINE_REGEX_CHECKS':
                for item in node.value.elts:
                    if not (isinstance(item, ast.Tuple) and len(item.elts) >= 2):
                        continue
                    item_name = item.elts[0]
                    if not (isinstance(item_name, ast.Constant) and isinstance(item_name.value, str)):
                        continue
                    item_name = item_name.value
                    item_re = item.elts[1]
                    if not (isinstance(item_re, ast.Call) and item_re.func.value.id == 'regex' and item_re.func.attr == 'compile' and len(item_re.args) >= 1):
                        continue
                    item_re = item_re.args[0]
                    if not (isinstance(item_re, ast.Constant) and isinstance(item_re.value, str)):
                        continue
                    item_re = item_re.value
                    self.line_regex_checks[item_name] = item_re



if __name__ == '__main__':
    main()
