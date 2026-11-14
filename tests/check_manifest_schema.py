"""Check published examples against the JSON Schema specification."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator


def main():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schema/manifest.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for name in ("evo-linux.json", "k8-mock.json"):
        data = json.loads((root / "tests/fixtures" / name).read_text(encoding="utf-8"))
        validator.validate(data)
        print(f"{name} is valid")


if __name__ == "__main__":
    main()