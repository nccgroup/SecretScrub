import json
import unittest

from secretscrub import *

class TestPlaceholder(unittest.TestCase):

    def test_generate_placeholder_with_custom_format_containing_basic_yaml_with_tool_name_none_sarif_rule_none_produces_no_detection(self):
        text = generate_placeholder('[TEST${yaml}]', None, None)
        assert text == "[TEST]"

    def test_generate_placeholder_with_custom_format_containing_basic_prefixed_yaml_with_custom_format_containing_space_prefixed_yaml_with_tool_name_set_sarif_rule_none_produces_detection_with_only_tool_name(self):
        text = generate_placeholder('[TEST${yaml}]', 'the_tool', None)
        assert text == "[TEST{Detection: {Tool: the_tool}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yaml_with_tool_name_none_sarif_rule_none_produces_no_detection(self):
        text = generate_placeholder('[TEST${_yaml}]', None, None)
        assert text == "[TEST]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yaml_with_custom_format_containing_space_prefixed_yaml_with_tool_name_set_sarif_rule_none_produces_detection_with_only_tool_name(self):
        text = generate_placeholder('[TEST${_yaml}]', 'the_tool', None)
        assert text == "[TEST {Detection: {Tool: the_tool}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yaml_with_tool_name_none_sarif_rule_with_name_set_regex_none_produces_detection_with_only_tool_name(self):
        sarif_rule = SarifRule(None, {'name':'the_rule'})
        text = generate_placeholder('[TEST${_yaml}]', None, sarif_rule)
        assert text == "[TEST {Detection: {Rule: the_rule}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yaml_with_tool_name_none_sarif_rule_with_name_set_regex_set_produces_detection_with_rule_name_regex(self):
        sarif_rule = SarifRule(None, {'name':'the_rule'})
        sarif_rule.regex = 'the_regex'
        text = generate_placeholder('[TEST${_yaml}]', None, sarif_rule)
        assert text == "[TEST {Detection: {Rule: the_rule}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yaml_with_tool_name_set_sarif_rule_with_name_set_regex_set_produces_detection_with_tool_name_rule_name_regex(self):
        sarif_rule = SarifRule('the_tool', {'name':'the_rule'})
        sarif_rule.regex = 'the_regex'
        text = generate_placeholder('[TEST${_yaml}]', 'the_tool', sarif_rule)
        assert text == "[TEST {Detection: {Tool: the_tool, Rule: the_rule}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yamlregex_with_regex_containing_colon_produces_no_detection(self):
        sarif_rule = SarifRule(None, {})
        sarif_rule.regex = 'the:regex'
        text = generate_placeholder('[TEST${_yaml_regex}]', None, sarif_rule)
        assert text == "[TEST {Detection: {Regex: the:regex}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yamlregex_with_regex_containing_colon_produces_detection_with_unquoted_regex(self):
        sarif_rule = SarifRule(None, {})
        sarif_rule.regex = 'the:regex'
        text = generate_placeholder('[TEST${_yaml_regex}]', None, sarif_rule)
        assert text == "[TEST {Detection: {Regex: the:regex}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yamlregex_with_regex_containing_complex_symbols_produces_detection_with_quoted_regex(self):
        sarif_rule = SarifRule(None, {})
        sarif_rule.regex = '(.*)(AKIA[A-Z0-9]{16})([^A-Z0-9][^\\n]*)'
        text = generate_placeholder('[TEST${_yaml_regex}]', None, sarif_rule)
        assert text == "[TEST {Detection: {Regex: '(.*)(AKIA[A-Z0-9]{16})([^A-Z0-9][^\\n]*)'}}]"

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yamlregex_with_regex_containing_single_quotes_produces_detection_with_double_quoted_regex(self):
        sarif_rule = SarifRule(None, {})
        sarif_rule.regex = "'.*'"
        text = generate_placeholder('[TEST${_yaml_regex}]', None, sarif_rule)
        assert text == '''[TEST {Detection: {Regex: "'.*'"}}]'''

    def test_generate_placeholder_with_custom_format_containing_space_prefixed_yamlregex_with_regex_containing_single_and_double_quotes_produces_detection_with_escaped_quoted_regex(self):
        sarif_rule = SarifRule(None, {})
        sarif_rule.regex = '''"'.*'"'''
        text = generate_placeholder('[TEST${_yaml_regex}]', None, sarif_rule)
        assert text == '''[TEST {Detection: {Regex: "\\"'.*'\\""}}]'''

    def test_generate_placeholder_with_custom_format_containing_tool_with_tool_name_set_sarif_rule_none_produces_tool_name(self):
        text = generate_placeholder('[TEST Tool: ${tool}]', 'the_tool', None)
        assert text == "[TEST Tool: the_tool]"

    def test_generate_placeholder_with_custom_format_containing_rule_with_rule_name_set_sarif_rule_none_produces_tool_name(self):
        sarif_rule = SarifRule(None, {'name': 'the_rule'})
        text = generate_placeholder('[TEST Rule: ${rule}]', None, sarif_rule)
        assert text == "[TEST Rule: the_rule]"

    def test_generate_placeholder_with_custom_format_containing_rule_with_rule_regex_set_sarif_rule_none_produces_tool_name(self):
        sarif_rule = SarifRule(None, {'name': 'the_rule'})
        sarif_rule.regex = 'the_regex'
        text = generate_placeholder('[TEST Regex: ${regex}]', None, sarif_rule)
        assert text == "[TEST Regex: the_regex]"

    def test_generate_placeholder_with_custom_format_containing_invalid_placeholder_produces_best_effort_string(self):
        sarif_rule = SarifRule(None, {'name': 'the_rule'})
        text = generate_placeholder('[TEST Rule: ${rule} Foo: ${bar}]', None, sarif_rule)
        assert text == "[TEST Rule: the_rule Foo: ${bar}]"


