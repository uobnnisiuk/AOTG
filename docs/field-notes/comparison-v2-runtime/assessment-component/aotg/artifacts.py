"""Canonical JSON and publication of immutable run artifacts."""

import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


class ArtifactError(ValueError):
    """An artifact is invalid or inconsistent with its recorded inputs."""


def canonical_json(value):
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactError("Duplicate JSON member")
        value[key] = item
    return value


def _reject_constant(value):
    raise ArtifactError(f"Non-finite JSON value '{value}'")


def read_artifact(path):
    with Path(path).open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ArtifactError("Artifact exceeds 1 MiB")
    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ArtifactError("Expected a JSON object")
    return value


def publish_artifact(path, document):
    output = Path(path)
    payload = json.dumps(
        document, allow_nan=False, ensure_ascii=True, sort_keys=True, indent=2
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(
            dir=output.parent, delete=False, mode="w", encoding="utf-8", newline="\n"
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload + "\n")
        if os.name == "nt":
            # Windows rename fails if the destination already exists.
            temporary.rename(output)
        else:
            # Linking publishes the complete file without replacing prior evidence.
            os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
