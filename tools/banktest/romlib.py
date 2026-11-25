"""Shared ROM-locating, manifest-reading and iNES helpers for the Python tools (bead grm-2a2a.1).

One implementation of "read the realrom manifest*.tsv files, resolve a row id or sha256 to an image
under the ROM dirs", plus the iNES header read and 16 KiB bank math that used to be copied around
tools/banktest and tools/recon. Not a CLI.

Importers must put this directory on sys.path first (`python -I` drops the script directory):

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'banktest'))
    import romlib

API:
  rom_dirs(env='GRM_ROM_DIR')           the dirs in an env var, split by the grm-3rel rule (a value
                                        containing ';' splits on ';' only, else on whitespace)
  manifest_rows(globs=None)             field lists of every data row (comments, blanks and the
                                        `id` header skipped); globs are names/patterns relative to
                                        tools/banktest/realrom, default manifest*.tsv (sorted)
  pin(row_id)                           the row's sha256 (last matching row wins), or None
  rom_files(env, exts, max_size)        image paths at depth 1 of the env var's dirs
  find_many(row_ids, ...)               {row_id: path}, hashing each image once
  find_path(row_id, ...)                path of one row's image; SystemExit with dis6502's
                                        messages if the row or the image is missing
  find_sha(sha, dirs, exts, max_size)   path of the image with that sha256 in explicit dirs
  parse_ines(path)                      (mapper, prg_bytes) or None; handles NES 2.0, DiskDude, trainer
  cpu_of(prgsize, off)                  CPU address of PRG offset off, last 16K bank at $C000

Defaults reproduce the old dis6502 behaviour: GRM_ROM_DIR, `.nes` files only. Pass exts=None for
any file (the old trialnorm-census-replay behaviour, with max_size 16 MiB).
"""
import glob
import hashlib
import os
import sys

REALROM_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           'tools', 'banktest', 'realrom')


def rom_dirs(env='GRM_ROM_DIR'):
    """Dirs in os.environ[env]. Same rule as realrom-test.sh (grm-3rel): a value containing ';'
    splits on ';' only (so a dir name may contain spaces), otherwise on any whitespace."""
    v = os.environ.get(env, '')
    return split_dirs(v)


def split_dirs(value):
    """The rom_dirs rule applied to an explicit string; empty parts dropped, parts trimmed."""
    parts = value.split(';') if ';' in value else value.split()
    return [p.strip() for p in parts if p.strip()]


def manifest_rows(globs=None):
    """Yield the field list of every data row of the selected manifests, in file order.

    globs: names or glob patterns relative to tools/banktest/realrom (default manifest*.tsv, whose
    matches are sorted). Explicit names are read in the order given; missing files are skipped.
    '#' comment lines, blank lines and the `id` header row are skipped."""
    for g in (globs or ['manifest*.tsv']):
        for m in sorted(glob.glob(os.path.join(REALROM_DIR, g))):
            with open(m, encoding='utf-8') as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    fields = line.rstrip('\n').split('\t')
                    if fields[0] == 'id':
                        continue
                    yield fields


def pin(row_id):
    sha = None
    for f in manifest_rows():
        if len(f) > 2 and f[0] == row_id:
            sha = f[2]
    return sha


def rom_files(env='GRM_ROM_DIR', exts=('.nes',), max_size=None):
    """Image paths at depth 1 of the dirs in env. exts: lowercase suffix tuple, or None for any
    regular file; max_size: skip larger files (None = no limit)."""
    return _files(rom_dirs(env), exts, max_size)


def _files(dirs, exts, max_size):
    for d in dirs:
        if exts is not None:
            cands = glob.glob(os.path.join(d, '*'))
            cands = [p for p in cands if p.lower().endswith(tuple(exts))]
        else:
            if not os.path.isdir(d):
                continue
            cands = [os.path.join(d, fn) for fn in os.listdir(d)]
            cands = [p for p in cands if os.path.isfile(p)]
        for p in cands:
            if max_size is None or os.path.getsize(p) < max_size:
                yield p


def _sha(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def find_many(row_ids, env='GRM_ROM_DIR', exts=('.nes',), max_size=None):
    """{row_id: path} for every row whose pinned image is under the env dirs, hashing each file
    once and stopping as soon as every row is found."""
    want = {}
    for r in row_ids:
        sha = pin(r)
        if sha:
            want.setdefault(sha, []).append(r)
    out = {}
    for p in rom_files(env, exts, max_size):
        if len(out) == sum(len(v) for v in want.values()):
            break
        for r in want.get(_sha(p), []):
            out.setdefault(r, p)
    return out


def find_path(row_id, env='GRM_ROM_DIR', exts=('.nes',), max_size=None):
    sha = pin(row_id)
    if sha is None:
        sys.exit('no manifest row ' + row_id)
    for p in rom_files(env, exts, max_size):
        if _sha(p) == sha:
            return p
    sys.exit('row %s (sha256 %s...) not found under $%s' % (row_id, sha[:12], env))


def find_sha(sha, dirs, exts=None, max_size=16 * 1024 * 1024):
    """Path of the file with this sha256 in explicit dirs (depth 1), or None. Defaults are the old
    trialnorm-census-replay behaviour: any regular file under 16 MiB."""
    for p in _files(dirs, exts, max_size):
        if _sha(p) == sha:
            return p
    return None


def parse_ines(path):
    """Return (mapper, prg_bytes) for an iNES file, or None if it is not one."""
    with open(path, 'rb') as f:
        raw = f.read()
    if raw[:4] != b'NES\x1a':
        return None
    prg16, f6, f7 = raw[4], raw[6], raw[7]
    mapper = (f6 >> 4) | (f7 & 0xF0)
    if (f7 & 0x0C) == 0x08:
        mapper |= (raw[8] & 0x0F) << 8
    elif raw[12:16] != b'\0\0\0\0':
        mapper &= 0x0F  # DiskDude header garbage
    off = 16 + (512 if f6 & 4 else 0)
    return mapper, raw[off: off + prg16 * 0x4000]


def cpu_of(prgsize, off):
    """CPU address of PRG offset `off` when the last 16K bank sits at $C000."""
    return 0xC000 + (off - (prgsize - 0x4000))
