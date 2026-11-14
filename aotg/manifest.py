"""Validate and load AOTG's versioned, environment manifest shape."""

import json
import re
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "manifest.schema.json"
_MAX_MANIFEST_BYTES = 1024 * 1024
_JSON_TYPES = {"object": dict, "array": list, "string": str, "integer": int,
               "boolean": bool, "null": type(None)}


class ManifestError(ValueError):
    """The manifest could not be read or failed the v1 contract."""


def load_manifest(path: str | Path) -> dict:
    """Read a bounded UTF-8 manifest and reject ambiguous JSON input."""
    try:
        with Path(path).open("rb") as source:
            content = source.read(_MAX_MANIFEST_BYTES + 1)
        if len(content) > _MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the 1 MiB size limit.")
        manifest = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except ManifestError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise ManifestError("Could not read a valid UTF-8 JSON manifest.") from None
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: object) -> None:
    """Raise ManifestError if the object violates the bundled v1 schema."""
    try:
        with SCHEMA_PATH.open(encoding="utf-8") as source:
            schema = json.load(source)
    except (OSError, ValueError):
        raise ManifestError("Could not load the bundled manifest schema.") from None
    _validate(manifest, schema, schema["$defs"], "manifest")
    for gpu in manifest["hardware"]["gpus"] or []:
        if gpu["memory_kind"] != "dedicated" and gpu["dedicated_vram_bytes"] is not None:
            raise ManifestError("Dedicated VRAM requires a dedicated memory kind.")
        if gpu["memory_kind"] != "shared" and gpu["uma_aperture_bytes"] is not None:
            raise ManifestError("A UMA aperture requires a shared memory kind.")
    hardware = manifest["hardware"]
    if (hardware["system_ram_bytes"] is None) != (hardware["system_ram_basis"] is None):
        raise ManifestError("System RAM size and basis must be supplied together.")


def _unique_object(items: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in items:
        if key in obj:
            raise ManifestError("Manifest contains duplicate object keys.")
        obj[key] = value
    return obj


def _same_json_value(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _validate(value: object, rule: dict, definitions: dict, label: str) -> None:
    """Apply the JSON Schema keywords used by the bundled schema."""
    reference = rule.get("$ref")
    if reference:
        _validate(value, definitions[reference.removeprefix("#/$defs/")], definitions, label)
    accepted_types = rule.get("type")
    if isinstance(accepted_types, str):
        accepted_types = [accepted_types]
    if accepted_types and type(value) not in [_JSON_TYPES[t] for t in accepted_types]:
        raise ManifestError(f"{label} has an invalid type.")
    if "const" in rule and not _same_json_value(value, rule["const"]):
        raise ManifestError(f"{label} has an unsupported value.")
    if "enum" in rule and not any(_same_json_value(value, option) for option in rule["enum"]):
        raise ManifestError(f"{label} has an unsupported value.")
    if isinstance(value, str) and "pattern" in rule and not re.fullmatch(rule["pattern"], value):
        raise ManifestError(f"{label} has an invalid format.")
    if type(value) is int and "minimum" in rule and value < rule["minimum"]:
        raise ManifestError(f"{label} is below the minimum.")
    if isinstance(value, dict) and "properties" in rule:
        properties = rule["properties"]
        for key in rule.get("required", []):
            if key not in value:
                raise ManifestError(f"{label}.{key} is required.")
        if rule.get("additionalProperties") is False and value.keys() - properties.keys():
            raise ManifestError(f"{label} contains an unexpected property.")
        for key, child in properties.items():
            if key in value:
                _validate(value[key], child, definitions, f"{label}.{key}")
    if isinstance(value, list) and "items" in rule:
        for index, item in enumerate(value):
            _validate(item, rule["items"], definitions, f"{label}[{index}]")
