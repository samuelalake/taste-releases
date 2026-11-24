"""Immutable upload followed by full reader-key verification; no application import."""
import json
from bundle import sha, require

BUCKET = 'taste-references'


def read_verified(reader, key, payload, content_type):
    response = reader.get_object(Bucket=BUCKET, Key=key)
    try:
        require(response['ContentLength'] == len(payload))
        require(response.get('Metadata', {}).get('sha256') == sha(payload))
        require(response.get('ContentType') == content_type)
        body = response['Body'].read(len(payload) + 1)
        require(len(body) == len(payload) and sha(body) == sha(payload))
    finally:
        response['Body'].close()


def immutable(writer, reader, key, payload, content_type):
    status = 'uploaded'
    try:
        writer.put_object(Bucket=BUCKET, Key=key, Body=payload,
                          ContentLength=len(payload), ContentType=content_type,
                          Metadata={'sha256': sha(payload)}, IfNoneMatch='*')
    except Exception as error:
        if getattr(error, 'response', {}).get('Error', {}).get('Code') not in ('PreconditionFailed', '412'):
            raise
        status = 'existing_verified'
    # Even a replay gets a full readback. No receipt alone permits skipping.
    read_verified(reader, key, payload, content_type)
    return status


def transfer(checked, writer, reader, batch_sha):
    totals = {'uploaded': 0, 'existing_verified': 0, 'bytes': 0}
    for row, payload in checked:
        status = immutable(writer, reader, row['objectKey'], payload, row['contentType'])
        # Deterministic receipts are private, survive interrupted jobs, and cannot overwrite.
        receipt = json.dumps({'queueSha256': batch_sha, 'key': row['objectKey'],
                              'sha256': row['sha256'], 'bytes': row['bytes'],
                              'readBack': 'passed'}, sort_keys=True).encode()
        immutable(writer, reader, 'imports/transfer-receipts/' + sha(receipt) + '.json',
                  receipt, 'application/json')
        totals[status] += 1
        totals['bytes'] += len(payload)
    return totals
