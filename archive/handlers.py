import logging
import os
import shutil
import tempfile

import util

import bz2
import gzip
import lzma
import tarfile
import zipfile

import py7zr

from .constants import CFG_NAME

class ArchiveHandler:
    def __init__(self):
        pass

    def unpack(self, mime_type, from_path, to_path):
        return False

    def repack(self, mime_type, from_path, to_path):
        return False
    
    # Like os.walk but filter out unpacked archive config files
    def walk(self, path):
        for (root, dirs, files) in os.walk(path):
            if CFG_NAME in files:
                files.remove(CFG_NAME)
            yield (root, dirs, files)

    def validate_paths(self, base_path, paths):
        base_path = util.os.path.realpath(base_path)
        for path in paths:
            if os.path.commonprefix([util.os.path.realpath(util.os.path.join(base_path, path)), base_path]) != base_path:
                logging.warn(f'Unsafe path detected: "{path}"')
                return False
            
        return True

class ZipArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with zipfile.ZipFile(from_path, 'r') as archive:
            if not self.validate_paths(to_path, archive.namelist()):
                return False
            archive.extractall(to_path)
            return True

    def repack(self, mime_type, from_path, to_path):
        with tempfile.NamedTemporaryFile('w+b', delete=False) as tmp_zip:
            tmp_path = tmp_zip.name
            with zipfile.ZipFile(tmp_zip, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        file_path = util.os.path.join(root, file_name)
                        arc_path = os.path.relpath(file_path, from_path)
                        archive.write(file_path, arc_path)
                        logging.info(f'File "{arc_path}" updated in archive "{to_path}".')

        shutil.move(tmp_path, to_path)
        return True

class SevenZipArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with py7zr.SevenZipFile(from_path) as archive:
            if not self.validate_paths(to_path, archive.getnames()):
                return False
            archive.extractall(to_path)
            return True

    def repack(self, mime_type, from_path, to_path):
        with tempfile.NamedTemporaryFile('w+b', delete=False) as tmp_zip:
            tmp_path = tmp_zip.name
            with py7zr.SevenZipFile(tmp_path, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        file_path = util.os.path.join(root, file_name)
                        arc_path = os.path.relpath(file_path, from_path)
                        archive.write(file_path, arc_path)
                        logging.info(f'File "{arc_path}" updated in archive "{to_path}".')

        shutil.move(tmp_path, to_path)
        return True
    
class GzipArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with gzip.open(from_path, 'rb') as archive:
            os.makedirs(to_path)
            new_file_name = os.path.basename(from_path)
            if new_file_name.endswith('.gz'):
                new_file_name = new_file_name[:-3]
            with open(util.os.path.join(to_path, new_file_name), 'wb') as f:
                shutil.copyfileobj(archive, f)

        return True

    def repack(self, mime_type, from_path, to_path):
        tmp_zip_dir = tempfile.mkdtemp()
        try:
            tmp_path = util.os.path.join(tmp_zip_dir, os.path.basename(to_path))
            with gzip.open(tmp_path, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        with open(util.os.path.join(root, file_name), 'rb') as f:
                            shutil.copyfileobj(f, archive)

            shutil.move(tmp_path, to_path)
        finally:
            shutil.rmtree(tmp_zip_dir)
        return True

class Bz2ArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with bz2.open(from_path, 'rb') as archive:
            os.makedirs(to_path)
            new_file_name = os.path.basename(from_path)
            if new_file_name.endswith('.gz'):
                new_file_name = new_file_name[:-3]
            with open(util.os.path.join(to_path, new_file_name), 'wb') as f:
                shutil.copyfileobj(archive, f)

        return True

    def repack(self, mime_type, from_path, to_path):
        tmp_zip_dir = tempfile.mkdtemp()
        try:
            tmp_path = util.os.path.join(tmp_zip_dir, os.path.basename(to_path))
            with bz2.open(tmp_path, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        with open(util.os.path.join(root, file_name), 'rb') as f:
                            shutil.copyfileobj(f, archive)

            shutil.move(tmp_path, to_path)
        finally:
            shutil.rmtree(tmp_zip_dir)
        return True

class LzmaArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with lzma.open(from_path, 'rb') as archive:
            os.makedirs(to_path)
            new_file_name = os.path.basename(from_path)
            if new_file_name.endswith('.gz'):
                new_file_name = new_file_name[:-3]
            with open(util.os.path.join(to_path, new_file_name), 'wb') as f:
                shutil.copyfileobj(archive, f)

        return True

    def repack(self, mime_type, from_path, to_path):
        tmp_zip_dir = tempfile.mkdtemp()
        try:
            tmp_path = util.os.path.join(tmp_zip_dir, os.path.basename(to_path))
            with lzma.open(tmp_path, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        with open(util.os.path.join(root, file_name), 'rb') as f:
                            shutil.copyfileobj(f, archive)

            shutil.move(tmp_path, to_path)
        finally:
            shutil.rmtree(tmp_zip_dir)
        return True


class TarArchiveHandler(ArchiveHandler):
    def __init__(self):
        super()

    def unpack(self, mime_type, from_path, to_path):
        with tarfile.open(from_path, 'r') as archive:
            if not self.validate_paths(to_path, archive.getnames()):
                return False
            archive.extractall(to_path)
            return True

    def repack(self, mime_type, from_path, to_path):
        with tempfile.NamedTemporaryFile('w+b', delete=False) as tmp_file:
            tmp_path = tmp_file.name
            with tarfile.open(tmp_path, 'w') as archive:
                for (root, dirs, files) in self.walk(from_path):
                    for file_name in files:
                        file_path = util.os.path.join(root, file_name)
                        arc_path = os.path.relpath(file_path, from_path)
                        archive.add(file_path, arc_path)
                        logging.info(f'File "{arc_path}" updated in archive "{to_path}".')

        shutil.move(tmp_path, to_path)
        return True

