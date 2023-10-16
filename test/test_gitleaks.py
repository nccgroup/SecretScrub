import json
import unittest

from secretscrub import *

class TestGitLeaks(unittest.TestCase):

    def test_detect_secret_span_on_line_1_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"aws-access-token has detected secret for file 001\\check_creds.py."},"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"001\\check_creds.py"},"region":{"startLine":1,"startColumn":22,"endLine":1,"endColumn":41,"snippet":{"text":"AKIAIOSFODNN73X4MPL3"}}}}],"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}')
        sarif_result = GitLeaksResult(sarif_result)
        line = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN73X4MPL3'\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match is not None
        assert match[0] == 21
        assert match[1] == 41

    def test_detect_secret_span_on_line_greater_than_1_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"aws-access-token has detected secret for file 001\\check_creds.py."},"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"001\\check_creds.py"},"region":{"startLine":3,"startColumn":23,"endLine":3,"endColumn":42,"snippet":{"text":"AKIAIOSFODNN73X4MPL3"}}}}],"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}')
        sarif_result = GitLeaksResult(sarif_result)
        line = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN73X4MPL3'\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match is not None
        assert match[0] == 21
        assert match[1] == 41

    def test_detect_secret_span_on_multi_line_span_with_blank_line_on_second_line_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"aws-access-token has detected secret for file 001\\check_creds.py."},"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"001\\check_creds.py"},"region":{"startLine":3,"startColumn":23,"endLine":4,"endColumn":1,"snippet":{"text":"AKIAIOSFODNN73X4MPL3"}}}}],"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}')
        sarif_result = GitLeaksResult(sarif_result)
        line = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN73X4MPL3'\r\n\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match is not None
        assert match[0] == 21
        assert match[1] == 41
