# magicpeek

A file's extension is a claim, not evidence. magicpeek reads the first bytes, names the real type, and tells you when the two disagree. Zero dependencies.

```console
$ magicpeek ~/Pictures
ok        /Users/me/Pictures/beach.png  PNG image
mismatch  /Users/me/Pictures/cat.jpg    Text file  (.jpg means jpeg, found text)
unknown   /Users/me/Pictures/blob.dat   unrecognised

3 file(s): 1 ok, 1 mismatch, 1 unknown, 0 without extension
```

## Install

```bash
pip install git+https://github.com/1252387328/magicpeek
```

## Commands

```bash
magicpeek photo.jpg                    # one file
magicpeek ~/Downloads                  # a directory, walked recursively
magicpeek --json ~/Downloads           # machine-readable
magicpeek -q ~/Downloads               # no output, exit code only
```

### Notes

- Recognises PNG, JPEG, GIF, WebP, BMP, TIFF, ICO, PDF, ZIP and the archive formats inside it (docx, xlsx, pptx, epub, apk, jar), gzip/bzip2/xz/zstd/7z/rar, ELF, Mach-O, PE, wasm, SQLite, MP3/FLAC/Ogg, MP4/WAV/AVI/MKV/WebM, fonts, HTML/XML and plain text.
- A mismatch is only reported when the extension is one magicpeek knows: `hook.sample` or `data.abc` is never flagged, while a text file named `readme.jpg` is.
- An extension the tool has never heard of cannot contradict the content, so it counts as `ok`.

Exit codes: `0` clean, `1` at least one mismatch, `2` path could not be read.

## Development

```bash
python -m unittest discover -s tests -v
```
