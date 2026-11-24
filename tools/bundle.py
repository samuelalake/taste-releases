"""Bounded, data-only reference bundles. Never execute anything supplied in a bundle."""
import hashlib
import io
import json
import re
import zipfile

MAX_BYTES = 64 * 1024 * 1024
MAX_OBJECT = 16 * 1024 * 1024
MAX_OBJECTS = 512
TYPES = {('images/imported', 'png'): 'image/png',
         ('images/imported', 'jpg'): 'image/jpeg',
         ('originals/imported', 'pdf'): 'application/pdf',
         ('imports/source-files', 'json'): 'application/json'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition):
    if not condition:
        raise ValueError('Bundle validation failed')


def unique_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def validate(data, expected_queue):
    require(len(data) <= MAX_BYTES)
    require(re.fullmatch('[0-9a-f]{64}', expected_queue))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        require(1 < len(members) <= MAX_OBJECTS + 1)
        names = [m.filename for m in members]
        require(len(set(names)) == len(names) and 'queue.json' in names)
        require(sum(m.file_size for m in members) <= MAX_BYTES)
        for member in members:
            require(member.compress_type == zipfile.ZIP_STORED)
            require(not member.is_dir() and member.file_size <= MAX_OBJECT)
            require(not member.flag_bits & 1)
        queue_bytes = archive.read('queue.json')
        require(len(queue_bytes) <= 1024 * 1024 and sha(queue_bytes) == expected_queue)
        queue = unique_json(queue_bytes)
        require(set(queue) == {'version', 'objects'} and queue['version'] == 1)
        rows = queue['objects']
        require(isinstance(rows, list) and 0 < len(rows) <= MAX_OBJECTS)
        expected_names, keys, checked = {'queue.json'}, set(), []
        for row in rows:
            require(isinstance(row, dict) and set(row) == {'objectKey', 'sha256', 'bytes', 'contentType'})
            match = re.fullmatch(r'(images/imported|originals/imported|imports/source-files)/([0-9a-f]{64})\.(png|jpg|pdf|json)', row['objectKey'])
            require(match is not None)
            prefix, digest, extension = match.groups()
            require(TYPES.get((prefix, extension)) == row['contentType'])
            require(digest == row['sha256'] and row['objectKey'] not in keys)
            require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_OBJECT)
            name = 'objects/' + digest + '.' + extension
            require(name in names)
            payload = archive.read(name)
            require(len(payload) == row['bytes'] and sha(payload) == digest)
            if extension == 'png': require(payload.startswith(b'\x89PNG\r\n\x1a\n'))
            if extension == 'jpg': require(payload.startswith(b'\xff\xd8\xff'))
            if extension == 'pdf': require(payload.startswith(b'%PDF-'))
            if extension == 'json': unique_json(payload)
            expected_names.add(name)
            keys.add(row['objectKey'])
            checked.append((row, payload))
        require(set(names) == expected_names)
        return checked


def pack(objects):
    """Producer helper: objects is [(allowed object key, content type, bytes)]."""
    rows = [{'objectKey': key, 'contentType': content_type,
             'bytes': len(data), 'sha256': sha(data)} for key, content_type, data in objects]
    queue = json.dumps({'version': 1, 'objects': rows}, sort_keys=True, separators=(',', ':')).encode()
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('queue.json', queue)
        for row, (_, _, data) in zip(rows, objects):
            archive.writestr('objects/' + row['objectKey'].split('/')[-1], data)
    data = result.getvalue()
    validate(data, sha(queue))
    return data, sha(queue)
