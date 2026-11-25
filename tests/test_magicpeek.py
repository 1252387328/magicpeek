import io
import json
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from magicpeek import audit, sniff
from magicpeek.cli import main

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 24
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 24
GIF = b"GIF89a" + b"\x00" * 26
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"\x00" * 16
GZIP = b"\x1f\x8b\x08\x00" + b"\x00" * 24
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 16
WAV = b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 16
SQLITE = b"SQLite format 3\x00" + b"\x00" * 32
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24
MP4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00" + b"\x00" * 20
HTML = b"<!DOCTYPE html>\n<html><body>hi</body></html>\n"
XML = b'<?xml version="1.0"?>\n<root/>\n'
TEXT = b"# Title\n\nSome words.\n"
GARBAGE = b"\x00\x01\x02\x03\x04\x05garbage\x00\x00"


def make_zip(path, names):
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return p


class SniffTests(Base):
    def test_known_signatures(self):
        cases = [
            ("a.png", PNG, "png", "PNG image"),
            ("a.jpg", JPEG, "jpeg", "JPEG image"),
            ("a.gif", GIF, "gif", "GIF image"),
            ("a.pdf", PDF, "pdf", "PDF document"),
            ("a.gz", GZIP, "gzip", "gzip archive"),
            ("a.webp", WEBP, "webp", "WebP image"),
            ("a.wav", WAV, "wav", "WAV audio"),
            ("a.sqlite", SQLITE, "sqlite", "SQLite database"),
            ("a.elf", ELF, "elf", "ELF binary"),
            ("a.mp4", MP4, "mp4", "MP4 video"),
        ]
        for name, data, kind, label in cases:
            got = sniff(self.write(name, data))
            self.assertEqual(got.kind, kind, name)
            self.assertEqual(got.label, label, name)

    def test_text_like(self):
        self.assertEqual(sniff(self.write("n.md", TEXT)).kind, "text")
        self.assertEqual(sniff(self.write("p.html", HTML)).kind, "html")
        self.assertEqual(sniff(self.write("x.xml", XML)).kind, "xml")
        self.assertEqual(sniff(self.write("s.svg", XML)).kind, "xml")

    def test_unknown_and_empty(self):
        self.assertIsNone(sniff(self.write("a.bin", GARBAGE)).kind)
        self.assertIsNone(sniff(self.write("empty", b"")).kind)

    def test_zip_family(self):
        docx = self.dir / "d.docx"
        make_zip(docx, ["[Content_Types].xml", "word/document.xml"])
        self.assertEqual(sniff(docx).kind, "docx")

        xlsx = self.dir / "d.xlsx"
        make_zip(xlsx, ["xl/workbook.xml"])
        self.assertEqual(sniff(xlsx).kind, "xlsx")

        apk = self.dir / "a.apk"
        make_zip(apk, ["AndroidManifest.xml", "classes.dex"])
        self.assertEqual(sniff(apk).kind, "apk")

        plain = self.dir / "p.zip"
        make_zip(plain, ["notes.txt"])
        self.assertEqual(sniff(plain).kind, "zip")


class AuditTests(Base):
    def test_ok(self):
        rec = audit([self.write("photo.png", PNG)])[0]
        self.assertEqual((rec.kind, rec.extension, rec.status), ("png", "png", "ok"))

    def test_mismatch(self):
        rec = audit([self.write("photo.jpg", PNG)])[0]
        self.assertEqual(rec.status, "mismatch")
        self.assertEqual(rec.extension, "jpg")

    def test_unknown(self):
        rec = audit([self.write("data.dat", GARBAGE)])[0]
        self.assertEqual(rec.status, "unknown")

    def test_no_extension(self):
        rec = audit([self.write("README", TEXT)])[0]
        self.assertEqual(rec.status, "no-ext")
        self.assertEqual(rec.extension, "")

    def test_text_family_accepts_many_extensions(self):
        for name in ["n.md", "n.txt", "n.json", "n.csv", "n.log"]:
            rec = audit([self.write(name, TEXT)])[0]
            self.assertEqual(rec.status, "ok", name)

    def test_docx_named_zip_is_a_mismatch(self):
        p = self.dir / "d.zip"
        make_zip(p, ["[Content_Types].xml", "word/document.xml"])
        self.assertEqual(audit([p])[0].status, "mismatch")

    def test_unknown_extension_is_never_a_mismatch(self):
        text = audit([self.write("hook.sample", TEXT)])[0]
        self.assertEqual(text.status, "ok")
        binary = audit([self.write("art.sample", PNG)])[0]
        self.assertEqual(binary.status, "ok")
        self.assertEqual(binary.kind, "png")

    def test_known_extension_still_flags_text_in_an_image(self):
        rec = audit([self.write("readme.jpg", TEXT)])[0]
        self.assertEqual(rec.status, "mismatch")

    def test_directory_is_walked(self):
        (self.dir / "sub").mkdir()
        self.write("one.png", PNG)
        (self.dir / "sub" / "two.jpg").write_bytes(JPEG)
        recs = audit([self.dir])
        names = sorted(r.path.name for r in recs)
        self.assertEqual(names, ["one.png", "two.jpg"])
        self.assertTrue(all(r.status == "ok" for r in recs))

    def test_results_are_sorted_by_path(self):
        self.write("b.png", PNG)
        self.write("a.pdf", PDF)
        self.assertEqual([r.path.name for r in audit([self.dir])], ["a.pdf", "b.png"])


class CliTests(Base):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_zero(self):
        code, out, _ = self.run_cli([str(self.write("a.png", PNG))])
        self.assertEqual(code, 0)
        self.assertIn("ok", out)

    def test_mismatch_exit_one(self):
        code, out, _ = self.run_cli([str(self.write("a.jpg", PNG))])
        self.assertEqual(code, 1)
        self.assertIn("mismatch", out)

    def test_json(self):
        self.write("a.jpg", PNG)
        code, out, _ = self.run_cli(["--json", str(self.dir)])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(len(data["files"]), 1)
        self.assertEqual(data["summary"]["mismatch"], 1)
        self.assertEqual(data["files"][0]["kind"], "png")

    def test_missing_path_exits_two(self):
        code, _, err = self.run_cli([str(self.dir / "nope.png")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err.lower())


if __name__ == "__main__":
    unittest.main()
