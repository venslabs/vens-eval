import hashlib
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from vkpi.sets import commit as c
from vkpi.sets.common import Refused, from_hex, load_json

SALT = bytes(range(32))
FILES = {
    "sealed/trivy.json": b'{"SchemaVersion": 2, "Results": []}\n',
    "contexts/c1/config.yaml": b"schema_version: 2\nproject:\n  name: ingest\n",
    "contexts/c3/config.yaml": b"schema_version: 2\nproject:\n  name: batch\n",
    "labels.jsonl": b"",
}


def write_tree(root, files):
    for rel, content in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = c.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class SetUnderTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.root = os.path.join(tmp.name, "set")
        write_tree(self.root, FILES)
        self.manifest, self.salts = c.commit(self.root, "demo")

    def salt(self, path):
        return bytes.fromhex(self.salts["salts"][path])


class TestFraming(unittest.TestCase):
    def test_the_bytes_of_a_file_commitment(self):
        spelled = ((22).to_bytes(8, "big") + b"vens-kpi/1.0/sets/file" + SALT
                   + (8).to_bytes(8, "big") + b"a/b.json" + (2).to_bytes(8, "big") + b"{}")
        value = c.file_commitment(SALT, "a/b.json", b"{}")
        self.assertEqual(value, hashlib.sha256(spelled).hexdigest())
        self.assertEqual(value, "95ac77d32ddad8357c93c2b29ae9e77d3104a81c033986c9e637b9451bc362a7")

    def test_the_bytes_of_an_aggregate(self):
        files = {"a/b.json": "95ac77d32ddad8357c93c2b29ae9e77d3104a81c033986c9e637b9451bc362a7"}
        canonical = ('{"files":{"a/b.json":"95ac77d32ddad8357c93c2b29ae9e77d3104a81c033986c9e637b9451bc362a7"},'
                     '"format":"vens-kpi/1.0/commitments","set":"demo"}').encode("ascii")
        spelled = ((27).to_bytes(8, "big") + b"vens-kpi/1.0/sets/aggregate"
                   + len(canonical).to_bytes(8, "big") + canonical)
        self.assertEqual(c.aggregate("demo", files), hashlib.sha256(spelled).hexdigest())
        self.assertEqual(c.aggregate("demo", files), "95c6c63c1c7a533850614cd3ebfa503de983e8dfb4409dce71284b23516d60bc")

    def test_path_and_content_cannot_trade_bytes(self):
        self.assertNotEqual(c.file_commitment(SALT, "ab", b"c"), c.file_commitment(SALT, "a", b"bc"))
        self.assertNotEqual(c.file_commitment(SALT, "a", b""), c.file_commitment(SALT, "a", b"\x00"))

    def test_paths_the_public_manifest_cannot_carry(self):
        for bad in ("", "/abs.json", "a//b", "../x", "./x", ".hidden", "a/.DS_Store", "a\\b", "é.json",
                    "cases/CVE-2099-0001.json", "x/GHSA-abcd-efgh-ijkl/a.json", "TEMP-0290435-0B57B5.json",
                    "CVE_2099_44228.json", "cve2099-44228.json", "CVE-2099/44228/a.json", "GHSA_abcd_efgh_ijkl.json"):
            with self.subTest(path=bad), self.assertRaises(Refused):
                c.check_path(bad)
        self.assertEqual(c.check_path("dir/pair-01/b+c_d.json"), "dir/pair-01/b+c_d.json")

    def test_a_salt_is_32_bytes(self):
        with self.assertRaises(Refused):
            c.file_commitment(SALT[:31], "a.json", b"")

    def test_hex_is_hex_and_nothing_else(self):
        self.assertEqual(from_hex("0A" * 32, 32, "salt"), b"\x0a" * 32)
        for bad in ("00" * 30 + "  " + "00", "00" * 31 + "0g", "00" * 31, "00" * 33, None):
            with self.subTest(text=bad), self.assertRaises(Refused):
                from_hex(bad, 32, "salt")


class TestRoundTrip(SetUnderTest):
    def test_the_committed_set_verifies(self):
        self.assertEqual(c.verify_set(self.root, self.manifest, self.salts), [])
        self.assertEqual(sorted(self.manifest["files"]), sorted(FILES))

    def test_each_file_reveals_alone(self):
        for path, content in FILES.items():
            with self.subTest(path=path):
                self.assertTrue(c.verify_file(self.manifest, path, self.salt(path), content))

    def test_salts_are_fresh_per_file_and_per_commit(self):
        salts = list(self.salts["salts"].values())
        self.assertEqual(len(set(salts)), len(salts))
        self.assertTrue(all(len(bytes.fromhex(salt)) == 32 for salt in salts))
        again, _ = c.commit(self.root, "demo")
        self.assertNotEqual(again["aggregate"], self.manifest["aggregate"])

    def test_the_manifest_holds_no_salt_and_no_content(self):
        text = repr(self.manifest)
        for path, content in FILES.items():
            self.assertNotIn(self.salts["salts"][path], text)
            if content:
                self.assertNotIn(content.decode(), text)


class TestTamper(SetUnderTest):
    def test_a_changed_byte(self):
        with open(os.path.join(self.root, "sealed", "trivy.json"), "ab") as fh:
            fh.write(b" ")
        self.assertEqual(c.verify_set(self.root, self.manifest, self.salts),
                         ["sealed/trivy.json: does not match its commitment"])

    def test_a_renamed_file(self):
        os.rename(os.path.join(self.root, "contexts", "c1"), os.path.join(self.root, "contexts", "c2"))
        self.assertEqual(c.verify_set(self.root, self.manifest, self.salts),
                         ["contexts/c1/config.yaml: missing", "contexts/c2/config.yaml: not in the manifest"])

    def test_an_added_file(self):
        write_tree(self.root, {"extra.json": b"{}"})
        self.assertEqual(c.verify_set(self.root, self.manifest, self.salts), ["extra.json: not in the manifest"])

    def test_an_edited_commitment_breaks_the_aggregate(self):
        files = dict(self.manifest["files"], **{"labels.jsonl": "0" * 64})
        with self.assertRaisesRegex(Refused, "manifest was altered"):
            c.check_manifest({**self.manifest, "files": files})

    def test_a_forged_manifest_does_not_take_the_salts(self):
        files = dict(self.manifest["files"], **{"labels.jsonl": "0" * 64})
        forged = {**self.manifest, "files": files, "aggregate": c.aggregate("demo", files)}
        with self.assertRaisesRegex(Refused, "another commit"):
            c.verify_set(self.root, forged, self.salts)
        self.assertFalse(c.verify_file(forged, "labels.jsonl", self.salt("labels.jsonl"), b""))

    def test_a_renamed_set_breaks_the_aggregate(self):
        with self.assertRaisesRegex(Refused, "manifest was altered"):
            c.check_manifest({**self.manifest, "set": "other"})


class TestWrongSalt(SetUnderTest):
    def test_the_salts_of_another_commit_are_refused(self):
        _, other = c.commit(self.root, "demo")
        with self.assertRaisesRegex(Refused, "another commit"):
            c.verify_set(self.root, self.manifest, other)

    def test_a_wrong_salt_does_not_open_a_file(self):
        path = "sealed/trivy.json"
        good = self.salt(path)
        self.assertFalse(c.verify_file(self.manifest, path, bytes([good[0] ^ 1]) + good[1:], FILES[path]))
        self.assertFalse(c.verify_file(self.manifest, path, self.salt("labels.jsonl"), FILES[path]))

    def test_swapped_salts(self):
        a, b = "contexts/c1/config.yaml", "contexts/c3/config.yaml"
        salts = dict(self.salts["salts"], **{a: self.salts["salts"][b], b: self.salts["salts"][a]})
        self.assertEqual(c.verify_set(self.root, self.manifest, {**self.salts, "salts": salts}),
                         [f"{a}: does not match its commitment", f"{b}: does not match its commitment"])


class TestRefusedFolders(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def test_a_symbolic_link(self):
        write_tree(self.root, {"a.json": b"{}"})
        os.symlink(os.path.join(self.root, "a.json"), os.path.join(self.root, "b.json"))
        with self.assertRaisesRegex(Refused, "symbolic link"):
            c.commit(self.root, "demo")

    def test_a_hidden_file(self):
        write_tree(self.root, {"a.json": b"{}", ".DS_Store": b""})
        with self.assertRaisesRegex(Refused, "starting with a dot"):
            c.commit(self.root, "demo")

    def test_a_file_named_after_a_cve(self):
        write_tree(self.root, {"CVE-2099-0001.json": b"{}"})
        with self.assertRaisesRegex(Refused, "vulnerability id"):
            c.commit(self.root, "demo")

    def test_an_empty_folder(self):
        with self.assertRaisesRegex(Refused, "no file"):
            c.commit(self.root, "demo")


class TestCli(SetUnderTest):
    def setUp(self):
        super().setUp()
        self.public = os.path.join(self.tmp, "public.json")
        self.private = os.path.join(self.tmp, "private", "salts.json")
        os.makedirs(os.path.dirname(self.private))

    def commit(self, *extra):
        return run("commit", self.root, "--set", "demo", "--manifest", self.public, "--salts", self.private, *extra)

    def test_commit_verify_and_reveal(self):
        code, out, _ = self.commit()
        self.assertEqual(code, 0)
        self.assertIn("committed 4 files of demo", out)
        self.assertEqual(stat.S_IMODE(os.stat(self.private).st_mode), 0o600)
        self.assertEqual(run("verify", self.root, "--manifest", self.public, "--salts", self.private)[0], 0)
        path = "sealed/trivy.json"
        self.assertEqual(run("verify", self.root, "--manifest", self.public, "--salts", self.private,
                             "--file", path)[0], 0)
        salt = load_json(self.private, "salts")["salts"][path]
        self.assertEqual(run("verify", self.root, "--manifest", self.public, "--salt", salt, "--file", path)[0], 0)
        content = os.path.join(self.root, *path.split("/"))
        self.assertEqual(run("reveal", "--manifest", self.public, "--path", path, "--salt", salt,
                             "--content", content)[0], 0)
        self.assertEqual(run("reveal", "--manifest", self.public, "--path", path, "--salt", "00" * 32,
                             "--content", content)[0], 1)
        with open(content, "ab") as fh:
            fh.write(b"\n")
        code, out, _ = run("verify", self.root, "--manifest", self.public, "--salts", self.private)
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 1 difference(s)", out)

    def test_salts_inside_a_git_working_tree_are_refused(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        self.private = os.path.join(repo, "salts.json")
        code, _, err = self.commit()
        self.assertEqual(code, 2)
        self.assertIn("git working tree", err)
        self.assertFalse(os.path.exists(self.private) or os.path.exists(self.public))

    def test_nothing_is_overwritten(self):
        with open(self.public, "w") as fh:
            fh.write("{}")
        code, _, err = self.commit()
        self.assertEqual(code, 2)
        self.assertIn("exists already", err)
        self.assertFalse(os.path.exists(self.private))

    def test_outputs_inside_the_committed_folder_are_refused(self):
        self.public = os.path.join(self.root, "public.json")
        code, _, err = self.commit()
        self.assertEqual(code, 2)
        self.assertIn("inside", err)

    def test_a_link_then_dot_dot_does_not_slip_the_salts_into_a_repository(self):
        repo, safe = os.path.join(self.tmp, "repo"), os.path.join(self.tmp, "safe")
        os.makedirs(os.path.join(repo, ".git"))
        os.makedirs(os.path.join(repo, "sub"))
        os.makedirs(safe)
        os.symlink(os.path.join(repo, "sub"), os.path.join(safe, "link"))
        self.private = os.path.join(safe, "link", "..", "salts.json")
        code, _, err = self.commit()
        self.assertEqual(code, 2)
        self.assertIn("git working tree", err)
        self.assertFalse(os.path.exists(os.path.join(repo, "salts.json")))
        self.private = os.path.join(self.tmp, "private", "salts.json")
        os.symlink(os.path.join(self.root, "contexts"), os.path.join(safe, "inside"))
        self.public = os.path.join(safe, "inside", "..", "public.json")
        code, _, err = self.commit()
        self.assertEqual(code, 2)
        self.assertIn("inside", err)

    def test_a_manifest_that_cannot_be_written_leaves_no_salts(self):
        self.public = os.path.join(self.tmp, "missing", "public.json")
        code, _, _ = self.commit()
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.private))

    def test_one_file_reached_through_a_link_is_refused(self):
        self.assertEqual(self.commit()[0], 0)
        path = "sealed/trivy.json"
        moved = os.path.join(self.tmp, "trivy.json")
        os.rename(os.path.join(self.root, "sealed", "trivy.json"), moved)
        os.symlink(moved, os.path.join(self.root, "sealed", "trivy.json"))
        code, _, err = run("verify", self.root, "--manifest", self.public, "--salts", self.private, "--file", path)
        self.assertEqual(code, 2)
        self.assertIn("symbolic link", err)


if __name__ == "__main__":
    unittest.main()
