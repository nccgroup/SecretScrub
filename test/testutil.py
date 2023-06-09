import os
import regex

def scan_folder_for_redacted_secrets(path):
    for (root, dirs, files) in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            with open(fpath, 'r') as f:
                for (line_index, line) in enumerate(f.readlines()):
                    for m in regex.finditer(r'\[REDACTED SECRET.*\]', line):
                        yield (fpath.replace('\\','/'), line_index, m.start, m.end)

