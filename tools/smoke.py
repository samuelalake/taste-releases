"""Actual age round-trip and fake storage, synthetic JSON only; no credential required."""
import io
import os
from pathlib import Path
import subprocess
import tempfile
from bundle import pack, sha, validate
from run import decrypt
from transfer import transfer


class PreconditionFailed(Exception):
    response = {'Error': {'Code': 'PreconditionFailed'}}


class Storage:
    def __init__(self): self.objects = {}
    def put_object(self, **request):
        assert request['IfNoneMatch'] == '*'
        key = request['Key']
        if key in self.objects: raise PreconditionFailed()
        self.objects[key] = request
    def get_object(self, **request):
        obj = self.objects[request['Key']]
        return {'Body': io.BytesIO(obj['Body']), 'ContentLength': obj['ContentLength'],
                'ContentType': obj['ContentType'], 'Metadata': obj['Metadata']}


def main():
    age = Path(os.environ['RUNNER_TEMP']) / 'taste-age'
    payload = b'{"synthetic":true,"purpose":"cloud-smoke"}'
    packed, fingerprint = pack([('imports/source-files/' + sha(payload) + '.json', 'application/json', payload)])
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
        folder = Path(temp)
        key = folder / 'generated-key'
        subprocess.run([str(age / 'age-keygen'), '-o', str(key)], capture_output=True, check=True, timeout=30)
        recipient = subprocess.run([str(age / 'age-keygen'), '-y', str(key)], capture_output=True, check=True, timeout=30).stdout.decode().strip()
        plain, sealed = folder / 'plain.zip', folder / 'sealed.age'
        plain.write_bytes(packed)
        subprocess.run([str(age / 'age'), '-r', recipient, '-o', str(sealed), str(plain)], capture_output=True, check=True, timeout=30)
        checked = validate(decrypt(sealed.read_bytes(), key.read_text(), recipient, age, folder), fingerprint)
        fake = Storage()
        assert transfer(checked, fake, fake, fingerprint)['uploaded'] == 1
        assert transfer(checked, fake, fake, fingerprint)['existing_verified'] == 1
        bad = bytearray(sealed.read_bytes()); bad[-1] ^= 1
        (folder / 'bundle.zip').unlink()
        try: decrypt(bytes(bad), key.read_text(), recipient, age, folder)
        except subprocess.CalledProcessError: pass
        else: raise AssertionError('Corruption accepted')
    print('Synthetic encryption, validation, immutable upload and replay passed')


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Synthetic smoke failed')
        raise SystemExit(1)
