import logging
import filetype
import json
import os
import shutil

from .constants import CFG_NAME
from .handlers import *

ARCHIVE_HANDLERS = {
    "application/zip" : ZipArchiveHandler,
    "application/x-7z-compressed" : SevenZipArchiveHandler,
    "application/gzip" : GzipArchiveHandler,
    "application/x-bzip2" : Bz2ArchiveHandler,
    "application/x-tar" : TarArchiveHandler,
    "application/x-xz" : LzmaArchiveHandler
}

def get_archive_handler(mime_type):
    if not mime_type in ARCHIVE_HANDLERS:
        return None
    
    return ARCHIVE_HANDLERS[mime_type]()

def unpack_archives(dir, report):
    final_result = True
    # Walk the entire directory before beginning processing. This is because the directory contents may
    # increase as individual archives are detected and expanded. Those will be handled recursively elsewhere.
    for archive_path, mime_type in list(walk_archives(dir)):
        result = unpack_archive(archive_path, mime_type, report)
        if not result:
            report.log_file_result(archive_path, 'ArchiveExtractionFailure', 'Archive file could not be extracted')
            final_result = False
    return final_result

def repack_archives(dir, report):
    final_result = True
    # Process in reverse sorted order, to ensure that inner archives are re-packed before the enclosing ones.
    for unpacked_path in sorted(walk_unpacked_archives(dir), reverse=True):
        result = repack_archive(unpacked_path)
        if not result:
            report.log_file_result(unpacked_path, 'ArchiveUpdateFailure', 'Archive file could not be updated')
            final_result = False
    return final_result

def walk_archives(dir):
    logging.debug(f'Walking {dir}')
    for root, dirs, files in os.walk(dir):
        for path in (os.path.join(root, f) for f in files):
            kind = filetype.guess(path)
            if kind is not None and kind.mime in (t.MIME for t in filetype.filetype.types if t.__module__.endswith('.archive')):
                yield (path, kind.mime)

def walk_unpacked_archives(dir):
    logging.debug(f'Walking {dir}...')
    for root, dirs, files in os.walk(dir):
        if CFG_NAME in files:
            yield root

def unpack_archive(archive_path, mime_type, report):
    archive_handler = get_archive_handler(mime_type)
    if not archive_handler:
        logging.warn(f'No registered handler for MIME type "{mime_type}"')
        return False
    
    archive_file_name = os.path.basename(archive_path)
    packed_path = os.path.join(os.path.dirname(archive_path), f'[[[{archive_file_name}]]]')

    try:
        logging.info(f'Unpacking archive file "{archive_path}"...')
        if os.path.isdir(packed_path):
            shutil.rmtree(packed_path)
        if not archive_handler.unpack(mime_type, archive_path, packed_path):
            return False
        with open(get_config_file_path(packed_path), 'w') as f:
            json.dump({'archive_name':os.path.basename(archive_path), 'mime_type':mime_type}, f)

    except Exception as e:
        logging.error(f'Error unpacking archive file "{archive_path}": {e}')
        return False

    unpack_archives(packed_path, report)
    return packed_path
    
def repack_archive(packed_path):
    try:
        cfg_path = get_config_file_path(packed_path)
        with open(cfg_path, 'r') as f:
            cfg = json.load(f)
    except Exception as e:
        logging.error(f'Error packing archive directory "{packed_path}": {e}')
        return False

    archive_name = cfg.get('archive_name')
    mime_type = cfg.get('mime_type')
    if not archive_name or not mime_type:
        logging.error(f'Missing content in unpacked archive configuration file "{cfg_path}"')
        return False

    archive_handler = get_archive_handler(mime_type)
    if not archive_handler:
        logging.warn(f'No registered handler for MIME type "{mime_type}"')
        return False
    
    try:
        if not archive_handler.repack(mime_type, packed_path, os.path.join(os.path.dirname(packed_path), archive_name)):
            return False
    except Exception as e:
        logging.error(f'Error packing archive directory "{packed_path}": {e}')
        return False
    
    shutil.rmtree(packed_path)
    return True

def get_config_file_path(unpacked_path):
    return os.path.join(unpacked_path, CFG_NAME)