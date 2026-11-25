"""Identify a file's real type from its magic bytes and compare it to the extension."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Union

__all__ = ["MagicpeekError", "Sniff", "Record", "sniff", "audit"]

HEAD_BYTES = 4096


class MagicpeekError(Exception):
    """A path could not be read or does not exist."""


@dataclass(frozen=True)
class Sniff:
    kind: Optional[str]
    label: str


@dataclass(frozen=True)
class Record:
    path: Path
    extension: str
    kind: Optional[str]
    label: str
    status: str


# (offset, signature, kind, label) — longest or most specific signatures first.
_SIGNATURES = [
    (0, b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (0, b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (0, b"GIF87a", "gif", "GIF image"),
    (0, b"GIF89a", "gif", "GIF image"),
    (0, b"%PDF-", "pdf", "PDF document"),
    (0, b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (0, b"\x1f\x8b", "gzip", "gzip archive"),
    (0, b"BZh", "bzip2", "bzip2 archive"),
    (0, b"\xfd7zXZ\x00", "xz", "xz archive"),
    (0, b"\x28\xb5\x2f\xfd", "zstd", "zstd archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (0, b"Rar!\x1a\x07", "rar", "RAR archive"),
    (0, b"\x7fELF", "elf", "ELF binary"),
    (0, b"\x00asm", "wasm", "WebAssembly module"),
    (0, b"OggS", "ogg", "Ogg stream"),
    (0, b"fLaC", "flac", "FLAC audio"),
    (0, b"ID3", "mp3", "MP3 audio"),
    (0, b"\xff\xfb", "mp3", "MP3 audio"),
    (0, b"\xff\xf3", "mp3", "MP3 audio"),
    (0, b"\xff\xf2", "mp3", "MP3 audio"),
    (0, b"wOFF", "woff", "WOFF font"),
    (0, b"wOF2", "woff", "WOFF font"),
    (0, b"OTTO", "otf", "OpenType font"),
    (0, b"\x00\x01\x00\x00\x00", "ttf", "TrueType font"),
    (0, b"\x00\x00\x01\x00", "ico", "ICO icon"),
    (0, b"II*\x00", "tiff", "TIFF image"),
    (0, b"MM\x00*", "tiff", "TIFF image"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O binary"),
    (0, b"\xce\xfa\xed\xfe", "macho", "Mach-O binary"),
    (0, b"\xfe\xed\xfa\xce", "macho", "Mach-O binary"),
    (0, b"\xfe\xed\xfa\xcf", "macho", "Mach-O binary"),
    (0, b"\xca\xfe\xba\xbe", "macho", "Mach-O universal binary"),
    (0, b"\x1a\x45\xdf\xa3", "matroska", "Matroska container"),
    (4, b"ftyp", "mp4", "MP4 video"),
    (0, b"MZ", "pe", "PE executable"),
]

KIND_EXTENSIONS = {
    "png": {"png"},
    "jpeg": {"jpg", "jpeg", "jpe", "jfif"},
    "gif": {"gif"},
    "webp": {"webp"},
    "bmp": {"bmp", "dib"},
    "tiff": {"tif", "tiff"},
    "ico": {"ico"},
    "pdf": {"pdf"},
    "zip": {"zip"},
    "docx": {"docx"},
    "xlsx": {"xlsx"},
    "pptx": {"pptx"},
    "epub": {"epub"},
    "apk": {"apk"},
    "jar": {"jar"},
    "gzip": {"gz", "gzip", "tgz"},
    "bzip2": {"bz2", "tbz2"},
    "xz": {"xz", "txz"},
    "zstd": {"zst", "zstd"},
    "7z": {"7z"},
    "rar": {"rar"},
    "elf": {"elf", "so", "o", "axf"},
    "macho": {"dylib", "bundle", "o"},
    "pe": {"exe", "dll", "sys", "cpl", "scr"},
    "wasm": {"wasm"},
    "sqlite": {"sqlite", "sqlite3", "db"},
    "mp3": {"mp3"},
    "ogg": {"ogg", "oga", "opus"},
    "flac": {"flac"},
    "wav": {"wav"},
    "mp4": {"mp4", "m4v", "m4a", "mov"},
    "webm": {"webm"},
    "mkv": {"mkv", "mka"},
    "avi": {"avi"},
    "woff": {"woff", "woff2"},
    "ttf": {"ttf"},
    "otf": {"otf"},
    "html": {"html", "htm", "xhtml"},
    "xml": {"xml", "svg", "plist", "rss", "atom", "xhtml"},
    "text": {
        "txt", "text", "md", "markdown", "rst", "adoc", "log", "csv", "tsv", "ini", "cfg",
        "conf", "toml", "yaml", "yml", "json", "jsonl", "ndjson", "py", "js", "mjs", "ts",
        "tsx", "jsx", "go", "rs", "c", "h", "cc", "cpp", "hpp", "java", "rb", "php", "sh",
        "bash", "zsh", "fish", "ps1", "sql", "css", "scss", "less", "tex", "patch", "diff",
        "env", "gitignore", "dockerfile", "makefile",
    },
}

# Reverse of KIND_EXTENSIONS: which kinds a given extension is normally used for.
# An extension missing from this map is one we know nothing about, so it is never
# reported as a mismatch.
EXT_KINDS = {}
for _kind, _extensions in KIND_EXTENSIONS.items():
    for _extension in _extensions:
        EXT_KINDS.setdefault(_extension, set()).add(_kind)
del _kind, _extensions, _extension


def _zip_kind(path: Path, head: bytes) -> Sniff:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            lowered = {name.lower() for name in names}
            if "mimetype" in names:
                try:
                    if b"application/epub+zip" in archive.read("mimetype"):
                        return Sniff("epub", "EPUB book")
                except (KeyError, OSError, RuntimeError):
                    pass
    except (zipfile.BadZipFile, OSError):
        return Sniff("zip", "ZIP archive")
    if "word/document.xml" in names:
        return Sniff("docx", "Word document")
    if "xl/workbook.xml" in names:
        return Sniff("xlsx", "Excel workbook")
    if "ppt/presentation.xml" in names:
        return Sniff("pptx", "PowerPoint deck")
    if "androidmanifest.xml" in lowered:
        return Sniff("apk", "Android package")
    if "meta-inf/manifest.mf" in lowered:
        return Sniff("jar", "Java archive")
    return Sniff("zip", "ZIP archive")


def _raster(head: bytes) -> Optional[Sniff]:
    if head[:4] == b"RIFF" and head[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return {
            b"WEBP": Sniff("webp", "WebP image"),
            b"WAVE": Sniff("wav", "WAV audio"),
            b"AVI ": Sniff("avi", "AVI video"),
        }[head[8:12]]
    if head[:4] == b"BM":
        return Sniff("bmp", "BMP image")
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return Sniff("webm", "WebM video") if b"webm" in head else Sniff("mkv", "Matroska video")
    return None


def _text_kind(head: bytes) -> Optional[Sniff]:
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = head.decode("utf-16")
        except UnicodeDecodeError:
            return None
    stripped = text.lstrip().lower()
    if stripped.startswith("<?xml"):
        return Sniff("xml", "XML document")
    if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
        return Sniff("html", "HTML document")
    sample = text[:512]
    if not sample:
        return None
    odd = sum(1 for char in sample if not (char.isprintable() or char in "\r\n\t"))
    if odd / len(sample) > 0.05:
        return None
    return Sniff("text", "Text file")


def sniff(path: Union[str, Path]) -> Sniff:
    """Guess the real type of ``path`` from its first bytes."""
    target = Path(path)
    try:
        with target.open("rb") as handle:
            head = handle.read(HEAD_BYTES)
    except FileNotFoundError:
        raise MagicpeekError("no such file or directory: %s" % target) from None
    except OSError as exc:
        raise MagicpeekError("cannot read %s: %s" % (target, exc)) from None

    if not head:
        return Sniff(None, "Empty file")
    special = _raster(head)
    if special is not None:
        return special
    if head[:2] == b"PK":
        return _zip_kind(target, head)
    for offset, signature, kind, label in _SIGNATURES:
        if head[offset : offset + len(signature)] == signature:
            return Sniff(kind, label)
    text = _text_kind(head)
    if text is not None:
        return text
    return Sniff(None, "unrecognised")


def _iter_files(paths: Sequence[Union[str, Path]]) -> Iterable[Path]:
    for item in paths:
        target = Path(item)
        if target.is_dir():
            for child in sorted(target.rglob("*")):
                if child.is_file():
                    yield child
        elif target.is_file():
            yield target
        else:
            raise MagicpeekError("no such file or directory: %s" % target)


def scan(path: Union[str, Path]) -> Record:
    """Sniff one file and compare the result with its extension."""
    target = Path(path)
    found = sniff(target)
    extension = target.suffix.lower().lstrip(".")
    if not extension:
        status = "no-ext"
    elif found.kind is None:
        status = "unknown"
    elif extension in KIND_EXTENSIONS.get(found.kind, set()):
        status = "ok"
    elif extension in EXT_KINDS:
        status = "mismatch"
    else:
        # An extension we know nothing about cannot contradict the content.
        status = "ok"
    return Record(target, extension, found.kind, found.label, status)


def audit(paths: Sequence[Union[str, Path]]) -> List[Record]:
    """Scan files (and directories, recursively) and return sorted records."""
    records = [scan(path) for path in _iter_files(paths)]
    records.sort(key=lambda record: str(record.path))
    return records
