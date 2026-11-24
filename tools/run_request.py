"""Decrypt a reviewed workflow request, then use the unchanged transfer path."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from bundle import require
from sealed_request import parse_request
from run import descriptor, main as transfer_main


def decrypt_descriptor(sealed, identity, recipient, age_dir, folder):
    key = folder / 'identity'
    key.write_text(identity)
    key.chmod(0o600)
    try:
        actual = subprocess.run([str(age_dir / 'age-keygen'), '-y', str(key)],
                                capture_output=True, timeout=30, check=True).stdout.decode().strip()
        require(actual == recipient)
        raw = subprocess.run([str(age_dir / 'age'), '--decrypt', '-i', str(key)], input=sealed,
                             capture_output=True, timeout=30, check=True).stdout
        require(len(raw) <= 4096)
        return raw.decode('utf-8')
    finally:
        key.unlink(missing_ok=True)


def main():
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    request, sealed = parse_request(event['inputs']['request'])
    with tempfile.TemporaryDirectory(prefix='taste-request-', dir=os.environ['RUNNER_TEMP']) as temp:
        raw = decrypt_descriptor(sealed, os.environ['TASTE_AGE_IDENTITY'], os.environ['TASTE_AGE_RECIPIENT'],
                                 Path(os.environ['RUNNER_TEMP']) / 'taste-age', Path(temp))
        descriptor(raw, request['batchId'], os.environ['TASTE_BUNDLE_HOST'])
        os.environ['TASTE_BATCH_ID'] = request['batchId']
        os.environ['TASTE_BATCH_CONFIG'] = raw
        transfer_main()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception:
        print('Transfer failed; no completion claimed; rerun verifies existing objects')
        raise SystemExit(1)
