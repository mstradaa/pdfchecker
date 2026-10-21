import hashlib
import os

from .coverage import check_coverage, print_coverage
from .threat_intel import check_file, selected_providers
from .urlhaus import URLhausClient
from .virustotal import VirusTotalClient


# Large enough to amortize Python-loop and read-call overhead while remaining
# small relative to the input size limit and friendly to concurrent hashing.
CHUNK_SIZE = 256 * 1024


def calculate_file_hashes(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
    except OSError as e:
        raise OSError(f"Error reading file {file_path}: {e}")

    return {
        'MD5': md5_hash.hexdigest(),
        'SHA-1': sha1_hash.hexdigest(),
        'SHA-256': sha256_hash.hexdigest()
    }

def main(file_path):
    print(f"\nCalculating hashes for {file_path}...")
    try:
        hashes = calculate_file_hashes(file_path)
    except OSError as e:
        print(f"Error: {e}")
        return

    print_coverage({'hashes': check_coverage('hashes', hashes)})
    for hash_type, hash_value in hashes.items():
        print(f"{hash_type}: {hash_value}")

    with selected_providers("this file", VirusTotalClient(), URLhausClient()) as providers:
        check_file(providers, hashes['SHA-256'])
