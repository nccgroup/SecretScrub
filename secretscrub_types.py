# Released as open source by NCC Group Plc - https://www.nccgroup.com/
#
# Developed by:
#     Andrew Kisliakov (andrew.kisliakov@nccgroup.com)
#
# Project link: https://www.github.com/nccgroup/secretscrub/
#
# Released under AGPL-3.0. See LICENSE for more information.

import base64

class SarifRule:
    def __init__(self, tool_name, sarif_rule):
        self.tool_name = tool_name
        self.id = get_from_dict(sarif_rule, ['id'])
        self.name = get_from_dict(sarif_rule, ['name'])
        self.regex =None
        self.is_secret = True

class SarifLocation:
    def __init__(self, sarif_location):
        self.artifact_path = get_from_dict(sarif_location, ['physicalLocation','artifactLocation','uri'])
        self.start_line = get_from_dict(sarif_location, ['physicalLocation','region','startLine'])
        self.start_column = get_from_dict(sarif_location, ['physicalLocation','region','startColumn'])
        self.byte_offset = get_from_dict(sarif_location, ['physicalLocation','region','byteOffset'])
        self.end_line = get_from_dict(sarif_location, ['physicalLocation','region','endLine'])
        self.end_column = get_from_dict(sarif_location, ['physicalLocation','region','endColumn'])
        self.byte_length = get_from_dict(sarif_location, ['physicalLocation','region','byteLength'])
        self.snippet_text = get_from_dict(sarif_location, ['physicalLocation','region','snippet','text'])
        snippet_binary = get_from_dict(sarif_location, ['physicalLocation','region','snippet','binary'])
        self.snippet_binary = None if not snippet_binary else base64.b64decode(snippet_binary)
        self.line_text = None
        
        # Adjust line and column numbers for 0-based indexing
        if self.start_line is not None:
            self.start_line = self.start_line - 1
        if self.start_column is not None:
            self.start_column = self.start_column - 1
        if self.end_line is not None:
            self.end_line = self.end_line - 1
        if self.end_column is not None:
            self.end_column = self.end_column - 1

class SarifResult:
    def __init__(self, tool_name, sarif_result):
        self.tool_name = tool_name
        self.rule_id = sarif_result.get('ruleId')
        self.rule_index = sarif_result.get('ruleIndex')
        self.commit_sha = get_from_dict(sarif_result, ['partialFingerprints','commitSha'])
        self.locations = list(SarifLocation(sarif_location) for sarif_location in sarif_result.get('locations',[]))
        self.message_text = get_from_dict(sarif_result, ['message','text'])
        self.message = self.message_text
        if len(self.locations) > 1:
            raise Exception("Result has multiple locations. This is not supported yet.")            

def get_from_dict(dict, path, default = None):
    node = dict
    for child in path:
        if not child in node:
            return default
        node = node[child]
    return node
