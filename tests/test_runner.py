import io
import json
from pathlib import Path
import sys
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from bundle import pack, sha, validate, unique_json
from gate import check
from run import descriptor
from smoke import Storage
from transfer import transfer


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.payload = b'{"synthetic":true}'
        self.key = 'imports/source-files/' + sha(self.payload) + '.json'
        self.bundle, self.fingerprint = pack([(self.key, 'application/json', self.payload)])

    def repack(self, mutate):
        with zipfile.ZipFile(io.BytesIO(self.bundle)) as archive:
            entries = {n: archive.read(n) for n in archive.namelist()}
        mutate(entries)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name, data in entries.items(): archive.writestr(name, data)
        return output.getvalue()

    def test_valid_batch(self):
        rows = validate(self.bundle, self.fingerprint)
        self.assertEqual(rows[0][1], self.payload)

    def test_approved_fingerprint_required(self):
        with self.assertRaises(ValueError): validate(self.bundle, '0' * 64)

    def test_bad_payload_fails_before_transfer(self):
        bad = self.repack(lambda e: e.update({'objects/' + self.key.split('/')[-1]: b'{"synthetic":false}'}))
        with self.assertRaises(ValueError): validate(bad, self.fingerprint)

    def test_extra_and_traversal_files_rejected(self):
        for name in ('extra.txt', '../outside', '/absolute'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(self.repack(lambda e: e.update({name: b'x'})), self.fingerprint)

    def test_compressed_archive_rejected(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('queue.json', b'{}'); z.writestr('x', b'x')
        with self.assertRaises(ValueError): validate(out.getvalue(), self.fingerprint)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError): unique_json('{"x":1,"x":2}')

    def test_duplicate_object_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with self.assertRaises(ValueError): pack([(self.key, 'application/json', self.payload)] * 2)

    def test_unapproved_key_and_type_rejected(self):
        for key, typ in [('manifest.json', 'application/json'), (self.key, 'text/html')]:
            with self.subTest(key=key, typ=typ), self.assertRaises(ValueError): pack([(key, typ, self.payload)])

    def test_full_readback_and_private_receipts(self):
        storage = Storage()
        checked = validate(self.bundle, self.fingerprint)
        self.assertEqual(transfer(checked, storage, storage, self.fingerprint)['uploaded'], 1)
        self.assertEqual(transfer(checked, storage, storage, self.fingerprint)['existing_verified'], 1)
        self.assertEqual(len(storage.objects), 2)
        self.assertTrue(any(k.startswith('imports/transfer-receipts/') for k in storage.objects))

    def test_mismatch_stops_without_receipt(self):
        storage = Storage()
        checked = validate(self.bundle, self.fingerprint)
        storage.put_object(Bucket='taste-references', Key=self.key, Body=b'wrong', ContentLength=5,
                           ContentType='application/json', Metadata={'sha256': sha(self.payload)}, IfNoneMatch='*')
        with self.assertRaises(ValueError): transfer(checked, storage, storage, self.fingerprint)
        self.assertEqual(len(storage.objects), 1)
        self.assertEqual(storage.objects[self.key]['Body'], b'wrong')

    def config(self):
        return {'batchId': 'a' * 32, 'expiresAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                'bundleUrl': 'https://files.example.com/encrypted.age', 'cipherSha256': 'b' * 64, 'queueSha256': self.fingerprint}

    def test_descriptor(self):
        self.assertEqual(descriptor(json.dumps(self.config()), 'a' * 32, 'files.example.com')['batchId'], 'a' * 32)

    def test_bad_host_scheme_identity_and_expiry(self):
        for updates in ({'bundleUrl': 'https://other.example.com/a'}, {'bundleUrl': 'http://files.example.com/a'},
                        {'bundleUrl': 'https://user:pass@files.example.com/a'}, {'batchId': 'c' * 32},
                        {'expiresAt': '2020-01-01T00:00:00Z'}):
            config = self.config(); config.update(updates)
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                descriptor(json.dumps(config), 'a' * 32, 'files.example.com')

    def policy(self):
        return {'can_admins_bypass': False,
                'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True},
                'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': False,
                                      'reviewers': [{'type': 'User', 'reviewer': {'id': 58840187}}]}]}

    def test_admission(self):
        check(self.policy(), {'branch_policies': [{'name': 'main', 'type': 'branch'}]})

    def test_missing_or_weakened_gate_denied(self):
        for change in ({'can_admins_bypass': True}, {'protection_rules': []}, {'deployment_branch_policy': None}):
            policy = self.policy(); policy.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                check(policy, {'branch_policies': [{'name': 'main', 'type': 'branch'}]})
        with self.assertRaises(ValueError): check(self.policy(), {'branch_policies': [{'name': '*', 'type': 'branch'}]})
        with self.assertRaises(ValueError): check(self.policy(), {'branch_policies': [{'name': 'main', 'type': 'tag'}]})


if __name__ == '__main__': unittest.main()
