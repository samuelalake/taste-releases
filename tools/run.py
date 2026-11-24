"""Private inputs enter only through protected environment secrets. Fixed public errors."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import urllib.parse
import urllib.request
from bundle import MAX_BYTES, require, sha, unique_json, validate
from transfer import transfer


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Redirect refused')


def descriptor(raw, batch_id, host):
    config = unique_json(raw)
    require(set(config) == {'batchId', 'expiresAt', 'bundleUrl', 'cipherSha256', 'queueSha256'})
    require(re.fullmatch('[0-9a-f]{32}', batch_id) and config['batchId'] == batch_id)
    for name in ('cipherSha256', 'queueSha256'):
        require(re.fullmatch('[0-9a-f]{64}', config[name]))
    remaining = (datetime.fromisoformat(config['expiresAt'].replace('Z', '+00:00')) - datetime.now(timezone.utc)).total_seconds()
    require(0 < remaining <= 86400)
    url = urllib.parse.urlsplit(config['bundleUrl'])
    require(url.scheme == 'https' and url.hostname == host and url.port in (None, 443))
    require(host and not url.username and not url.password and not url.fragment)
    # Host is separately owner-configured, never chosen by the queue.
    require(re.fullmatch('[a-z0-9.-]+', host) and '.' in host)
    return config


def download(config, host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    require(addresses and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses))
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    with opener.open(config['bundleUrl'], timeout=60) as response:
        data = response.read(MAX_BYTES + 1024 * 1024 + 1)
    require(len(data) <= MAX_BYTES + 1024 * 1024 and sha(data) == config['cipherSha256'])
    return data


def decrypt(ciphertext, identity, recipient, age_dir, folder):
    key = folder / 'identity'
    key.write_text(identity)
    key.chmod(0o600)
    derived = subprocess.run([str(age_dir / 'age-keygen'), '-y', str(key)], capture_output=True, timeout=30, check=True).stdout.decode().strip()
    require(derived == recipient)
    sealed, plain = folder / 'bundle.age', folder / 'bundle.zip'
    sealed.write_bytes(ciphertext)
    try:
        subprocess.run([str(age_dir / 'age'), '--decrypt', '-i', str(key), '-o', str(plain), str(sealed)],
                       capture_output=True, timeout=120, check=True)
        require(plain.stat().st_size <= MAX_BYTES)
        return plain.read_bytes()
    finally:
        key.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    batch = os.environ['TASTE_BATCH_ID']
    host = os.environ['TASTE_BUNDLE_HOST']
    config = descriptor(os.environ['TASTE_BATCH_CONFIG'], batch, host)
    with tempfile.TemporaryDirectory(prefix='taste-private-', dir=os.environ['RUNNER_TEMP']) as temp:
        checked = validate(decrypt(download(config, host), os.environ['TASTE_AGE_IDENTITY'],
                                  os.environ['TASTE_AGE_RECIPIENT'],
                                  Path(os.environ['RUNNER_TEMP']) / 'taste-age', Path(temp)), config['queueSha256'])
        if not args.execute:
            print('Bundle validated; no storage writes')
            return
        import boto3
        from botocore.config import Config
        account = os.environ['TASTE_R2_ACCOUNT_ID']
        require(re.fullmatch('[0-9a-f]{32}', account))
        def client(role):
            return boto3.client('s3', endpoint_url=f'https://{account}.r2.cloudflarestorage.com',
                                region_name='auto', aws_access_key_id=os.environ[f'TASTE_R2_{role}_ACCESS_KEY_ID'],
                                aws_secret_access_key=os.environ[f'TASTE_R2_{role}_SECRET_ACCESS_KEY'],
                                config=Config(signature_version='s3v4', retries={'mode': 'standard', 'max_attempts': 3},
                                              connect_timeout=15, read_timeout=60,
                                              request_checksum_calculation='when_required', response_checksum_validation='when_required'))
        totals = transfer(checked, client('WRITER'), client('READER'), config['queueSha256'])
        print(json.dumps(totals, sort_keys=True))
        print('Transfer and full readback passed; library metadata unchanged')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception:
        # Never print exception messages: SDK/network errors can contain private inputs.
        print('Transfer failed; no completion claimed; rerun verifies existing objects')
        raise SystemExit(1)
