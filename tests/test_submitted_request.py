import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sealed_request import parse_request, pack_request
from run_request import decrypt_descriptor, main


class SubmittedRequestTests(unittest.TestCase):
    def setUp(self):
        self.batch = 'a' * 32
        self.sealed = b'age-encryption.org/v1\n' + b'x' * 150
        self.body = pack_request(self.batch, self.sealed)

    def test_valid_bounded_request(self):
        request, sealed = parse_request(self.body)
        self.assertEqual(request['batchId'], self.batch)
        self.assertEqual(sealed, self.sealed)

    def test_no_plaintext_or_extra_fields(self):
        for body in ('https://files.example.com/private', '[]', '{}', self.body + 'x'):
            with self.subTest(body=body), self.assertRaises((ValueError, json.JSONDecodeError)):
                parse_request(body)
        data = json.loads(self.body); data['bundleUrl'] = 'https://files.example.com/private'
        with self.assertRaises(ValueError): parse_request(json.dumps(data))

    def test_tampered_hash_size_and_encoding(self):
        for changes in ({'descriptorSha256': '0' * 64}, {'sealedDescriptor': '!'},
                        {'sealedDescriptor': base64.b64encode(b'plain text').decode()},
                        {'batchId': '../../secret'}, {'version': True}):
            data = json.loads(self.body); data.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): parse_request(json.dumps(data))
        with self.assertRaises(ValueError): pack_request(self.batch, self.sealed * 100)
        with self.assertRaises(ValueError): parse_request(' ' * 17000)

    def test_expired_or_changed_identity_never_reaches_transfer(self):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / 'event.json'; event.write_text(json.dumps({'inputs': {'request': self.body}}))
            env = {'GITHUB_EVENT_PATH': str(event), 'RUNNER_TEMP': temp, 'TASTE_AGE_IDENTITY': 'synthetic',
                   'TASTE_AGE_RECIPIENT': 'synthetic', 'TASTE_BUNDLE_HOST': 'files.example.com'}
            for changes in ({'expiresAt': '2020-01-01T00:00:00Z'}, {'batchId': 'b' * 32},
                            {'bundleUrl': 'https://other.example.com/a'}):
                config = {'batchId': self.batch, 'expiresAt': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                          'bundleUrl': 'https://files.example.com/a', 'cipherSha256': 'b'*64, 'queueSha256': 'c'*64}
                config.update(changes)
                with self.subTest(changes=changes), patch.dict(os.environ, env), \
                     patch('run_request.decrypt_descriptor', return_value=json.dumps(config)), \
                     patch('run_request.transfer_main') as transfer:
                    with self.assertRaises(ValueError): main()
                    transfer.assert_not_called()

    def test_reuses_existing_transfer_path(self):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / 'event.json'; event.write_text(json.dumps({'inputs': {'request': self.body}}))
            config = {'batchId': self.batch, 'expiresAt': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                      'bundleUrl': 'https://files.example.com/a', 'cipherSha256': 'b'*64, 'queueSha256': 'c'*64}
            env = {'GITHUB_EVENT_PATH': str(event), 'RUNNER_TEMP': temp, 'TASTE_AGE_IDENTITY': 'synthetic',
                   'TASTE_AGE_RECIPIENT': 'synthetic', 'TASTE_BUNDLE_HOST': 'files.example.com'}
            with patch.dict(os.environ, env), patch('run_request.decrypt_descriptor', return_value=json.dumps(config)), \
                 patch('run_request.transfer_main') as transfer:
                main(); transfer.assert_called_once()
                self.assertEqual(json.loads(os.environ['TASTE_BATCH_CONFIG']), config)

    @unittest.skipUnless(os.environ.get('TASTE_TEST_AGE_DIR'), 'explicit pinned age directory required')
    def test_real_age_roundtrip_and_wrong_recipient(self):
        age = Path(os.environ['TASTE_TEST_AGE_DIR']).resolve()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); identity_path = folder / 'generated'
            subprocess.run([str(age/'age-keygen'), '-o', str(identity_path)], capture_output=True, check=True)
            identity = identity_path.read_text()
            recipient = subprocess.run([str(age/'age-keygen'), '-y', str(identity_path)], capture_output=True, check=True).stdout.decode().strip()
            raw = b'{"synthetic":"no real credentials"}'
            sealed = subprocess.run([str(age/'age'), '-r', recipient], input=raw, capture_output=True, check=True).stdout
            request, decoded = parse_request(pack_request(self.batch, sealed))
            self.assertEqual(decrypt_descriptor(decoded, identity, recipient, age, folder), raw.decode())
            self.assertFalse((folder/'identity').exists())
            with self.assertRaises(ValueError): decrypt_descriptor(decoded, identity, 'wrong', age, folder)
            self.assertFalse((folder/'identity').exists())


if __name__ == '__main__': unittest.main()
