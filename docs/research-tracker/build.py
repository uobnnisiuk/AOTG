#!/usr/bin/env python3
"""Build the portable AOTG tracker without network access or dependencies."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MARKER = '__SEED_JSON__'


def render():
    template = (ROOT / 'template.html').read_text(encoding='utf-8')
    if template.count(MARKER) != 1:
        raise ValueError('Expected exactly one seed placeholder in template.html')
    seed = json.loads((ROOT / 'seed.json').read_text(encoding='utf-8'))
    if seed.get('schemaVersion') != 1 or not isinstance(seed.get('records'), list):
        raise ValueError('Unsupported seed schema')
    ids = [r['id'] for r in seed['records']]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate record IDs in seed.json')
    payload = json.dumps(seed, ensure_ascii=False, indent=2).replace('</', '<\\/')
    return template.replace(MARKER, payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check that index.html matches sources')
    args = parser.parse_args()
    output = ROOT / 'index.html'
    rendered = render()
    if args.check:
        if not output.exists() or output.read_text(encoding='utf-8') != rendered:
            raise SystemExit('index.html is stale; run python build.py')
        print('OK: index.html matches template.html + seed.json')
    else:
        output.write_text(rendered, encoding='utf-8')
        print('Generated index.html')


if __name__ == '__main__':
    main()
