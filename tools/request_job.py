"""Producer CLI: encrypt an existing private descriptor into a public-safe request."""
import argparse
import json
from pathlib import Path
import subprocess
from sealed_request import pack_request
from run import descriptor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--descriptor', type=Path, required=True)
    parser.add_argument('--age', type=Path, required=True)
    parser.add_argument('--recipient', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.descriptor.read_text()
    value = json.loads(raw)
    descriptor(raw, value['batchId'], args.host)
    sealed = subprocess.run([str(args.age), '-r', args.recipient], input=raw.encode(),
                            capture_output=True, timeout=30, check=True).stdout
    args.output.write_text(pack_request(value['batchId'], sealed) + '\n')
    print('Encrypted job request written; no credentials or plaintext URLs included')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Request preparation failed')
        raise SystemExit(1)
