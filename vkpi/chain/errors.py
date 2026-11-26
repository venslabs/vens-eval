"""What the reader refuses, and the JSON files it reads, a file cut mid-write refused by name."""
import json


class Refused(Exception):
    """A folder the reader will not read: a download it cannot tell from another, a file cut short, or one its
    dispatch log or its expected commits contradict."""


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(f"{path}: not readable as JSON, a file cut short or corrupted: {e}") from e


def load_object(path):
    """A JSON file that must hold one object: a record, provenance.json or run.json."""
    doc = load_json(path)
    if not isinstance(doc, dict):
        raise Refused(f"{path}: a JSON {type(doc).__name__}, not an object")
    return doc
