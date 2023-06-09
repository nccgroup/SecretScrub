import os
import shutil
import unittest

from parameterized import parameterized

from secretscrub import main as secretscrub_main, DEFAULT_PLACEHOLDER_FORMAT
from secretscrub_report import SecretScrubReportEncryption

from .testutil import scan_folder_for_redacted_secrets

class Args:
    def __init__(self):
        self.log_level = None
        self.analyse_with = None
        self.input = None
        self.srcdir = None
        self.outdir = None
        self.placeholder = DEFAULT_PLACEHOLDER_FORMAT
        self.report = None
        self.report_encryption = SecretScrubReportEncryption.ZIP_AES256
        self.process_archives = False

class TestMain(unittest.TestCase):

    @parameterized.expand(['bin'])
    def test_main_analysewith_bindetect(self, subdir):
        outdir = self.invoke_secretscrub('bindetect', subdir)
        detected_secrets = list(scan_folder_for_redacted_secrets(outdir))
        assert len(detected_secrets) > 0

    @parameterized.expand(['aws'])
    def test_main_analysewith_ccs(self, subdir):
        outdir = self.invoke_secretscrub('ccs', subdir)
        detected_secrets = list(scan_folder_for_redacted_secrets(outdir))
        assert len(detected_secrets) > 0

    @parameterized.expand(['aws','ssh'])
    def test_main_analysewith_cq(self, subdir):
        outdir = self.invoke_secretscrub('cq', subdir)
        detected_secrets = list(scan_folder_for_redacted_secrets(outdir))
        assert len(detected_secrets) > 0

    @parameterized.expand(['aws','jwt','ssh'])
    def test_main_analysewith_gitleaks(self, subdir):
        outdir = self.invoke_secretscrub('gitleaks', subdir)
        detected_secrets = list(scan_folder_for_redacted_secrets(outdir))
        assert len(detected_secrets) > 0

    @parameterized.expand(['aws'])
    def test_main_analysewith_trivy(self, subdir):
        outdir = self.invoke_secretscrub('trivy', subdir)
        detected_secrets = list(scan_folder_for_redacted_secrets(outdir))
        assert len(detected_secrets) > 0


    def invoke_secretscrub(self, analyse_with, data_dir):
        srcdir = os.path.join(os.path.dirname(__file__), 'data', data_dir)
        outdir =  os.path.join(os.path.dirname(__file__), 'data-redacted', data_dir)
        shutil.rmtree(outdir, ignore_errors=True)
        args = Args()
        args.analyse_with = analyse_with
        args.srcdir = srcdir
        args.outdir = outdir
        secretscrub_main(args)
        assert os.path.isdir(outdir)
        return outdir