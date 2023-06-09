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
import json
import os
import regex
import sys

def main():
    global args
    args = parse_args()
    ccs_results_stream = open(args.input, 'r') if args.input else sys.stdin
    ccs_results = ccs_results_stream.read()
    ccs_to_sarif(args.ccs, args.srcdir, ccs_results, args.out)
    if args.input:
        ccs_results_stream.close()

def ccs_to_sarif(ccs_path, src_dir, ccs_results, out_path):
    ccs = Ccs(ccs_path)
    sarif_rules = build_rules(ccs)
    sarif_tool = build_sarif_tool(sarif_rules)
    sarif_findings = process_sarif_findings(sarif_rules, src_dir, ccs_results)
    sarif_doc = build_sarif_doc(sarif_tool, sarif_findings)
    try:
        out_file = open(out_path, 'w') if out_path else sys.stdout 
        json.dump(sarif_doc, out_file, indent=2)
    finally:
        if out_path:
            out_file.close()

def parse_args():
    parser = argparse.ArgumentParser(prog = __file__)
    parser.add_argument('-c', '--ccs', required=True)
    parser.add_argument('-i', '--input')
    parser.add_argument('-s', '--srcdir', required=True)
    parser.add_argument('-o', '--out')
    args = parser.parse_args()

    if not args.srcdir:
        args.srcdir = os.getcwd()

    return args

def build_rules(ccs):
    sarif_rules = []
    for line_regex_check in ccs.line_regex_checks:
        tags = []
        if line_regex_check.startswith('cred_'):
            tags.append('secret')
        sarif_rules.append({
            'id' : line_regex_check,
            'name' : line_regex_check.replace('-',' ').replace('_',' '),
            'shortDescription' : {
                'text' : ccs.line_regex_checks[line_regex_check]
            },
            'properties' : {
                'tags' : tags
            }
        })
    return sarif_rules

def build_sarif_tool(sarif_rules):
    tool_def = {
        'driver' : {
            'fullName' : 'ccs',
            'informationUri' : 'https://github.com/chris-anley/ccs',
            'name' : 'ccs',
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

def process_sarif_findings(sarif_rules, src_dir, ccs_results):
    lines = list(line.rstrip('\r') for line in ccs_results.split('\n'))

    for line in lines:
        (src_path, src_line, rule_id, src_prefix, src_text) = parse_ccs_output_line(line)
        if not src_path:
            continue

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
def parse_ccs_output_line(line):
    split = line.split(':')
    if WINDOWS_PATH_REGEX.match(line):
        split = [(split[0] + ':' + split[1])] + split[2:]
    if len(split) < 7:
        return (None, None, None, None, None)
    return (split[0], int(split[1]), ':'.join(split[2:5]), split[5], split[6])

def get_path_relative_to(path, dir):
    try:
        relpath = os.path.relpath(path, dir)
        if relpath.startswith('..' + os.pathsep):
            return None
        return relpath.replace('\\', '/')
    except:
        return None

# Represents the ccs.py file that was used to generate the ccs output being processed. This contains
# a list of regular expressions that are parsed out from the file using Python's built-in AST analyzer.
class Ccs:
    def __init__(self, path):
        ccspy_path = os.path.join(path, 'ccs.py') if not path.endswith('.py') else path
        with open(ccspy_path, "r") as ccspy_file:
            ccspy_ast = ast.parse(ccspy_file.read())

        analyzer = CcsRegexAnalyzer()
        analyzer.visit(ccspy_ast)
        self.line_regex_checks = analyzer.line_regex_checks

class CcsRegexAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.line_regex_checks = {}
        self.consts = {}

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                    self.consts[target.id] = node.value.value
                elif target.id == 'pwd_rules':
                    for item in node.value.elts:
                        if not (isinstance(item, ast.Tuple) and len(item.elts) >= 4):
                            continue
                        item_rule_number = item.elts[1]
                        if not (isinstance(item_rule_number, ast.Constant) and isinstance(item_rule_number.value, int)):
                            continue
                        item_rule_number = item_rule_number.value
                        item_rule_type = item.elts[2]
                        if not (isinstance(item_rule_type, ast.Constant) and isinstance(item_rule_type.value, str)):
                            continue
                        item_rule_type = item_rule_type.value
                        item_name = f'{item_rule_type}:Rule:{item_rule_number}'
                        item_re = item.elts[0]
                        if not (isinstance(item_re, ast.Call) and item_re.func.value.id == 're' and item_re.func.attr == 'compile' and len(item_re.args) >= 1):
                            continue
                        item_re = item_re.args[0]
                        # TODO: The regex is built in a complex way
                        # if not (isinstance(item_re, ast.Constant) and isinstance(item_re.value, str)):
                        #     continue
                        item_re = self.build_string(item_re)
                        self.line_regex_checks[item_name] = item_re

    def build_string(self, ast_item):
        if isinstance(ast_item, ast.Constant):
            return str(ast_item.value)
        if isinstance(ast_item, ast.Name):
            if ast_item.id not in self.consts:
                raise f"No constant value known with name {ast_item.id}"
            return self.consts[ast_item.id]
        if isinstance(ast_item, ast.BinOp):
            return self.build_string(ast_item.left) + self.build_string(ast_item.right)
        
        raise f"Don't know how to build a string containing {ast_item}"


if __name__ == '__main__':
    main()
