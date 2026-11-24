"""Install the same hash-pinned official age release as May's control repo."""
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

PINS = {
    ('Linux', 'x86_64'): ('linux-amd64', 'bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377'),
    ('Darwin', 'arm64'): ('darwin-arm64', '01120ea2cbf0463d4c6bd767f99f3271bbed1cdc8a9aa718a76ba1fe4f01998b'),
}


def install():
    target, expected = PINS[(platform.system(), platform.machine())]
    url = f'https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-{target}.tar.gz'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Tool checksum mismatch')
    directory = Path(os.environ['RUNNER_TEMP']) / 'taste-age'
    directory.mkdir(mode=0o700, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for name in ('age', 'age-keygen'):
            member = archive.getmember('age/' + name)
            if not member.isfile() or member.size > 24 * 1024 * 1024:
                raise ValueError('Invalid tool archive')
            output = directory / name
            output.write_bytes(archive.extractfile(member).read())
            output.chmod(0o700)
    return directory


if __name__ == '__main__':
    try:
        install()
        print('Pinned encryption tool installed')
    except Exception:
        print('Encryption tool installation failed')
        raise SystemExit(1)
