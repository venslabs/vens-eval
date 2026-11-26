"""What the set tools share: the refusal they raise, strict JSON, hex parsing, and the rule that keeps private files
out of every git working tree."""
import hashlib
import json
import os
import re

_HEX = re.compile(r"[0-9a-fA-F]*")


class Refused(Exception):
    """An input, a path or a record the set tools will not use, with the reason."""


def canonical_json(obj):
    """The bytes hashed: keys sorted, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pretty_json(obj):
    """The bytes written to a file: keys sorted and indented, so the same object always gives the same file."""
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def parse_json(text, what):
    """JSON refused on a duplicate key or a NaN, either of which could hide a second value."""
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError) as e:
        raise Refused(f"{what}: not valid JSON: {e}") from e


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        raise Refused(f"{what} {path}: {e}") from e
    return parse_json(text, f"{what} {path}")


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def from_hex(text, size, what):
    """Exactly `size` bytes written as hex, in either case, nothing else."""
    if not isinstance(text, str) or not _HEX.fullmatch(text) or len(text) != 2 * size:
        raise Refused(f"{what}: expected {2 * size} hex characters")
    return bytes.fromhex(text)


def worktree_of(path):
    """The nearest folder at or above where `path` lands, symbolic links resolved, that holds a `.git` entry."""
    # realpath alone: abspath would fold "link/.." before the link is followed, and miss where the file lands.
    current = os.path.dirname(os.path.realpath(path))
    while True:
        if os.path.lexists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def require_private(path, what):
    root = worktree_of(path)
    if root is not None:
        raise Refused(f"{what} {path} is inside the git working tree {root}: private files stay out of every "
                      "repository")


def is_inside(path, folder):
    target = os.path.realpath(path)
    base = os.path.realpath(folder)
    return os.path.commonpath([target, base]) == base


def write_new(path, data, private=False):
    """Writes `data` to a file that must not exist yet; a private file is readable by its owner only."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    except FileExistsError as e:
        raise Refused(f"{path} exists already: nothing is overwritten") from e
    except OSError as e:
        raise Refused(f"{path}: {e.strerror}") from e
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        os.unlink(path)
        raise
