import json
import unittest

from secretscrub import *

class TestTrivy(unittest.TestCase):

    def test_detect_secret_span_without_newlines_and_no_match_in_prefix_should_return_none(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.+TST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST+.1({[<>]})1.-TSETtset(<SECRET>)TST+.1({[<>]})1.+TST!!!!!!!!!!\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 0

    def test_detect_secret_span_without_newlines_and_no_match_in_suffix_should_return_none(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.+TST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST+.1({[<>]})1.+TSETtset(<SECRET>)TST+.1({[<>]})1.-TST!!!!!!!!!!\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 0

    def test_detect_secret_span_without_newlines_and_asterisks_in_prefix_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST1234testTEST****testTE**********testTEST1234testTEST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST1234testTEST****testTE(<SECRET>)testTEST1234testTEST!!!!!!!!!!\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match is not None
        assert match[0] == 40
        assert match[1] == 50

    def test_detect_secret_span_without_newlines_and_simple_prefix_suffix_and_unix_style_input_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST1234testTEST1234testTE**********testTEST1234testTEST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST1234testTEST1234testTE(<SECRET>)testTEST1234testTEST!!!!!!!!!!\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match[0] == 40
        assert match[1] == 50

    def test_detect_secret_span_without_newlines_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.+TST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST+.1({[<>]})1.+TSETtset(<SECRET>)TST+.1({[<>]})1.+TST!!!!!!!!!!\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match[0] == 40
        assert match[1] == 50

    def test_detect_secret_span_with_newline_in_prefix_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: tes\nTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.+TST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "TEST+.1({[<>]})1.+TSETtset(<SECRET>)TST+.1({[<>]})1.+TST!!!!!!!!!!\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match[0] == 26
        assert match[1] == 36

    def test_detect_secret_span_with_newline_in_suffix_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: testTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.\nTST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "!!!!!!!!!!testTEST+.1({[<>]})1.+TSETtset(<SECRET>)TST+.1({[<>]})1.\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match[0] == 40
        assert match[1] == 50

    def test_detect_secret_span_with_newline_in_prefix_and_suffix_should_return_correct_start_and_end(self):
        sarif_result = json.loads(r'{"message":{"text":"Artifact: text.txt\nType: \nTest Type\nSeverity: HIGH\nMatch: tes\nTEST+.1({[<>]})1.+TSETtset**********TST+.1({[<>]})1.\nTST"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"test-file.txt"},"region":{"startLine":2,"startColumn":1,"endLine":2,"endColumn":1}}}], "id":"test-id", "name":"test name"}')
        sarif_result = TrivyResult(sarif_result)
        line = "TEST+.1({[<>]})1.+TSETtset(<SECRET>)TST+.1({[<>]})1.\r\n"
        matches = list(sarif_result.detect_secret_spans(sarif_result.locations[0], line))
        assert len(matches) == 1
        match = matches[0]
        assert match[0] == 26
        assert match[1] == 36


if __name__ == '__main__':
    unittest.main()