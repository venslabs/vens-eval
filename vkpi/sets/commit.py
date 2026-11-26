"""Salted commitments to a private set of files.

The public manifest names each file and its commitment; the salts stay private until a file is revealed. With
frame(x) = len(x) as 8 bytes, big-endian, followed by x:

    file commitment = SHA-256( frame(b"vens-kpi/1.0/sets/file")
                             || salt              32 bytes from `secrets.token_bytes`, one per file, not framed
                             || frame(path)       the relative path, `/`-separated, UTF-8, as the manifest spells it
                             || frame(content) )  the file's bytes, unchanged

    aggregate       = SHA-256( frame(b"vens-kpi/1.0/sets/aggregate") || frame(canonical) )

canonical is the JSON object {"files": {path: commitment}, "format": "vens-kpi/1.0/commitments", "set": name}, keys
sorted, no whitespace, ASCII. The manifest is that object plus "aggregate"; its layout on disk plays no part.

Paths are public. Each `/`-separated part is ASCII letters, digits and `_ . + -`, not starting with a dot, and a path
naming a vulnerability id (CVE-, GHSA-, TEMP-) is refused, since the manifest would reveal it.

    python3 -m vkpi.sets.commit commit ROOT --set NAME --manifest PUBLIC.json --salts PRIVATE.json
    python3 -m vkpi.sets.commit verify ROOT --manifest PUBLIC.json --salts PRIVATE.json [--file PATH]
    python3 -m vkpi.sets.commit verify ROOT --manifest PUBLIC.json --salt HEX --file PATH
    python3 -m vkpi.sets.commit reveal --manifest PUBLIC.json --path PATH --salt HEX --content FILE
"""
import argparse
import hashlib
import os
import re
import secrets
import sys

from vkpi.sets.common import (Refused, canonical_json, framed as frame, from_hex, is_inside, load_json, pretty_json,
                              require_private, write_new)

FORMAT = "vens-kpi/1.0/commitments"
SALTS_FORMAT = "vens-kpi/1.0/salts"
FILE_TAG = b"vens-kpi/1.0/sets/file"
AGGREGATE_TAG = b"vens-kpi/1.0/sets/aggregate"
SALT_BYTES = 32

_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]*")
_SEP = r"[-_./+]*"
_VULN_ID = re.compile(rf"CVE{_SEP}\d{{4}}{_SEP}\d{{4}}"
                      rf"|GHSA(?:{_SEP}[0-9a-z]{{4}}){{3}}"
                      rf"|TEMP{_SEP}\d{{7}}{_SEP}[0-9a-f]{{6}}", re.IGNORECASE)
_SET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_COMMITMENT = re.compile(r"[0-9a-f]{64}")


def shown(path):
    """A path as a refusal may print it: any vulnerability id in it masked."""
    return _VULN_ID.sub("<id>", path) if isinstance(path, str) else f"a {type(path).__name__}"


def check_path(path):
    """A path the public manifest may name."""
    if not isinstance(path, str) or not all(_PART.fullmatch(part) for part in path.split("/")):
        raise Refused(f"{shown(path)!r}: a path is `/`-separated parts of ASCII letters, digits and _ . + -, none "
                      "starting with a dot")
    if _VULN_ID.search(path):
        raise Refused(f"{shown(path)}: names a vulnerability id (CVE, GHSA or TEMP, whatever the separator), which "
                      "the public manifest would reveal; use an opaque name")
    return path


def check_set_name(name):
    if not isinstance(name, str) or not _SET_NAME.fullmatch(name):
        raise Refused(f"{name!r}: a set name is ASCII letters, digits and . _ -, at most 100 characters")
    return name


def file_commitment(salt, path, content):
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise Refused(f"a salt is {SALT_BYTES} bytes")
    check_path(path)
    digest = hashlib.sha256(frame(FILE_TAG))
    digest.update(salt)
    digest.update(frame(path.encode("utf-8")))
    digest.update(frame(content))
    return digest.hexdigest()


def aggregate(set_name, files):
    body = {"files": dict(files), "format": FORMAT, "set": set_name}
    return hashlib.sha256(frame(AGGREGATE_TAG) + frame(canonical_json(body))).hexdigest()


def list_files(root):
    """Every regular file under `root`, as sorted relative paths. A link, a special file or a name the manifest
    cannot carry is refused, never skipped."""
    if not os.path.isdir(root):
        raise Refused(f"{root} is not a folder")
    found, pending = [], [""]
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(os.path.join(root, folder)) as entries:
                listed = list(entries)
        except OSError as e:
            raise Refused(f"{folder or root}: {e.strerror}") from e
        for entry in listed:
            rel = check_path(f"{folder}/{entry.name}" if folder else entry.name)
            if entry.is_symlink():
                raise Refused(f"{rel}: a symbolic link; commit the file itself")
            if entry.is_dir(follow_symlinks=False):
                pending.append(rel)
            elif entry.is_file(follow_symlinks=False):
                found.append(rel)
            else:
                raise Refused(f"{rel}: not a regular file")
    return sorted(found)


def read_file(root, path):
    """The bytes of one file of the set, refused when its path goes through a symbolic link, as `list_files` does."""
    parts = check_path(path).split("/")
    if any(os.path.islink(os.path.join(root, *parts[:depth])) for depth in range(1, len(parts) + 1)):
        raise Refused(f"{path}: goes through a symbolic link")
    try:
        with open(os.path.join(root, *parts), "rb") as fh:
            return fh.read()
    except OSError as e:
        raise Refused(f"{path}: {e.strerror}") from e


def commit(root, set_name):
    """The public manifest and the private salts of every file under `root`, a fresh salt per file."""
    check_set_name(set_name)
    paths = list_files(root)
    if not paths:
        raise Refused(f"{root}: no file to commit")
    salts = {path: secrets.token_bytes(SALT_BYTES) for path in paths}
    files = {path: file_commitment(salts[path], path, read_file(root, path)) for path in paths}
    total = aggregate(set_name, files)
    manifest = {"aggregate": total, "files": files, "format": FORMAT, "set": set_name}
    private = {"aggregate": total, "format": SALTS_FORMAT, "salts": {path: salt.hex() for path, salt in salts.items()},
               "set": set_name}
    return manifest, private


def check_manifest(manifest):
    """The manifest's files, once its form is checked and its aggregate is the one its files give."""
    if not isinstance(manifest, dict) or set(manifest) != {"aggregate", "files", "format", "set"}:
        raise Refused("a manifest holds exactly aggregate, files, format and set")
    if manifest["format"] != FORMAT:
        raise Refused(f"manifest format {manifest['format']!r}, expected {FORMAT}")
    check_set_name(manifest["set"])
    files = manifest["files"]
    if not isinstance(files, dict) or not files:
        raise Refused("a manifest names at least one file")
    for path, value in files.items():
        check_path(path)
        if not isinstance(value, str) or not _COMMITMENT.fullmatch(value):
            raise Refused(f"{path}: a commitment is 64 lowercase hex characters")
    if manifest["aggregate"] != aggregate(manifest["set"], files):
        raise Refused("the aggregate does not match the files: the manifest was altered")
    return files


def check_salts(private, manifest):
    """The salts by path, once they are known to come from the commit that made this manifest."""
    if not isinstance(private, dict) or set(private) != {"aggregate", "format", "salts", "set"}:
        raise Refused("a salts file holds exactly aggregate, format, salts and set")
    if private["format"] != SALTS_FORMAT:
        raise Refused(f"salts format {private['format']!r}, expected {SALTS_FORMAT}")
    if private["set"] != manifest["set"] or private["aggregate"] != manifest["aggregate"]:
        raise Refused("these salts come from another commit than the manifest's")
    if not isinstance(private["salts"], dict):
        raise Refused("salts: a map from path to salt")
    return {path: from_hex(value, SALT_BYTES, f"salt of {shown(path)}") for path, value in private["salts"].items()}


def verify_file(manifest, path, salt, content):
    """True when `content` under `path` and `salt` gives the manifest's commitment."""
    files = check_manifest(manifest)
    if path not in files:
        raise Refused(f"{shown(path)} is not in the manifest of {manifest['set']}")
    return file_commitment(salt, path, content) == files[path]


def verify_set(root, manifest, private):
    """Every difference between the files under `root` and the committed set; none means it is the same set."""
    files = check_manifest(manifest)
    salts = check_salts(private, manifest)
    on_disk = set(list_files(root))
    problems = []
    for path in sorted(files):
        if path not in on_disk:
            problems.append(f"{path}: missing")
        elif path not in salts:
            problems.append(f"{path}: no salt")
        elif file_commitment(salts[path], path, read_file(root, path)) != files[path]:
            problems.append(f"{path}: does not match its commitment")
    problems.extend(f"{path}: not in the manifest" for path in sorted(on_disk - set(files)))
    return problems


def _cmd_commit(args):
    for path, what in ((args.salts, "the salts file"), (args.manifest, "the manifest")):
        if is_inside(path, args.root):
            raise Refused(f"{what} {path} is inside {args.root}, the folder it commits")
        if os.path.lexists(path):
            raise Refused(f"{path} exists already: nothing is overwritten")
    require_private(args.salts, "the salts file")
    manifest, private = commit(args.root, args.set)
    write_new(args.salts, pretty_json(private), private=True)
    try:
        write_new(args.manifest, pretty_json(manifest))
    except BaseException:
        os.unlink(args.salts)
        raise
    print(f"committed {len(manifest['files'])} files of {args.set}, aggregate {manifest['aggregate']}")
    print(f"public manifest: {args.manifest}")
    print(f"private salts: {args.salts}")
    return 0


def _one_result(path, manifest, ok):
    if ok:
        print(f"ok: {path} matches its commitment in {manifest['set']} (aggregate {manifest['aggregate']})")
        return 0
    print(f"FAIL: {path} does not match its commitment in {manifest['set']}")
    return 1


def _cmd_verify(args):
    manifest = load_json(args.manifest, "manifest")
    if args.salt is not None:
        if args.file is None:
            raise Refused("--salt checks one file: give --file")
        salt = from_hex(args.salt, SALT_BYTES, "--salt")
        return _one_result(args.file, manifest, verify_file(manifest, args.file, salt, read_file(args.root, args.file)))
    private = load_json(args.salts, "salts file")
    if args.file is not None:
        salts = check_salts(private, manifest)
        if args.file not in salts:
            raise Refused(f"no salt for {shown(args.file)}")
        content = read_file(args.root, args.file)
        return _one_result(args.file, manifest, verify_file(manifest, args.file, salts[args.file], content))
    problems = verify_set(args.root, manifest, private)
    for line in problems:
        print(line)
    if problems:
        print(f"FAIL: {len(problems)} difference(s) with the set {manifest['set']}")
        return 1
    print(f"ok: the {len(manifest['files'])} files under {args.root} are the set {manifest['set']} "
          f"(aggregate {manifest['aggregate']})")
    return 0


def _cmd_reveal(args):
    manifest = load_json(args.manifest, "manifest")
    salt = from_hex(args.salt, SALT_BYTES, "--salt")
    try:
        with open(args.content, "rb") as fh:
            content = fh.read()
    except OSError as e:
        raise Refused(f"{args.content}: {e.strerror}") from e
    return _one_result(args.path, manifest, verify_file(manifest, args.path, salt, content))


def _parser():
    parser = argparse.ArgumentParser(prog="python3 -m vkpi.sets.commit",
                                     description="Salted commitments to a private set of files.")
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("commit", help="commit every file under ROOT")
    cmd.add_argument("root")
    cmd.add_argument("--set", required=True, help="the set's name, bound into the aggregate")
    cmd.add_argument("--manifest", required=True, help="the public manifest to write")
    cmd.add_argument("--salts", required=True, help="the private salts to write, outside every git working tree")
    cmd = sub.add_parser("verify", help="check the files under ROOT, or one of them, against the manifest")
    cmd.add_argument("root")
    cmd.add_argument("--manifest", required=True)
    given = cmd.add_mutually_exclusive_group(required=True)
    given.add_argument("--salts", help="the private salts file")
    given.add_argument("--salt", help="one file's salt, in hex, with --file")
    cmd.add_argument("--file", help="the path of one file, as the manifest names it")
    cmd = sub.add_parser("reveal", help="check a revealed file: its path, salt and content")
    cmd.add_argument("--manifest", required=True)
    cmd.add_argument("--path", required=True, help="the path the manifest names")
    cmd.add_argument("--salt", required=True, help="the revealed salt, in hex")
    cmd.add_argument("--content", required=True, help="the revealed file")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        return {"commit": _cmd_commit, "verify": _cmd_verify, "reveal": _cmd_reveal}[args.command](args)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
