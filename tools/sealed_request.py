"""Submitted request contains only an age-encrypted descriptor; never source metadata."""
import base64
import binascii
import hashlib
import json
import re
from bundle import require, unique_json

MAX_REQUEST = 16_384


def parse_request(body):
    require(isinstance(body, str) and len(body.encode()) <= MAX_REQUEST)
    request = unique_json(body)
    require(isinstance(request, dict))
    require(set(request) == {'version', 'batchId', 'descriptorSha256', 'sealedDescriptor'})
    require(type(request['version']) is int and request['version'] == 1)
    require(isinstance(request['batchId'], str) and re.fullmatch('[0-9a-f]{32}', request['batchId']))
    require(isinstance(request['descriptorSha256'], str) and re.fullmatch('[0-9a-f]{64}', request['descriptorSha256']))
    require(isinstance(request['sealedDescriptor'], str))
    try:
        sealed = base64.b64decode(request['sealedDescriptor'], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('Invalid request') from None
    require(100 <= len(sealed) <= 10_240 and sealed.startswith(b'age-encryption.org/v1\n'))
    require(hashlib.sha256(sealed).hexdigest() == request['descriptorSha256'])
    return request, sealed


def pack_request(batch_id, sealed):
    request = {'version': 1, 'batchId': batch_id,
               'descriptorSha256': hashlib.sha256(sealed).hexdigest(),
               'sealedDescriptor': base64.b64encode(sealed).decode('ascii')}
    body = json.dumps(request, separators=(',', ':'))
    parse_request(body)
    return body
