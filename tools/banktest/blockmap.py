"""Loader block name -> ROM image offset, per platform (bead grm-2a2a.5). Not a CLI.

dis6502.py's `<row-id> <block>:<addr>` mode uses this to turn the name a golden dump or a bead
prints (`PRG_LO_B5`, `W8000_M3_B31`, `WC000`) into the bytes the loader put in that block, by the
SAME rules NesRomLoader uses -- driven by the board descriptor in machines/<board>.yaml (and the
per-game `banking: initial_state` hint in machines/games/*.yaml whose identity.prg_sha256 matches),
not by a second hand-kept table.

NES block naming (OverlayNaming.java, NesRomLoader.realize*Window):
  <window>           the window's HOME instance: home layout mode, home bank (initial_state)
  <window>_B<n>      invariant (or collapsed single-layout) switchable window, state field = n
  <window>_M<m>      mode-varying FIXED window's instance for layout mode m (non-home layout)
  <window>_M<m>_B<n> mode-varying switchable window, layout mode m, state field = n
n is the banking.state FIELD VALUE (a register value), not a byte offset; the window's maps:
expression turns it into a PRG offset, and only canonical values (v & decodedMask == v) name a
block. With no _M the instance of the HOME layout mode is used (the loader drops the other modes
when assume_initial_layout_mode is set, which is what the *_B<n> names in MMC1/MMC3 goldens are).

Seam for other CPUs: RESOLVERS maps a platform key to `resolve(row, image_path, block_name) ->
BlockView`. Only 'nes' (6502) is implemented; 65816 / SPC700 readers register another resolver
and reuse BlockView. BlockView.label(addr) names where a CPU address lives, for table targets.

Needs PyYAML (the descriptors are YAML); a missing module is reported, not worked around.
"""
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import romlib  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BlockError(Exception):
    """A block name that cannot be mapped (the message says why and what is available)."""


class BlockView:
    """One resolved block: `data` is its bytes, CPU addresses [start, end), `prg_off` the offset
    of its first byte within the PRG payload, `file_off` the same within the image file."""

    def __init__(self, name, start, end, data, prg_off, file_off, labeler=None, note=''):
        self.name, self.start, self.end, self.data = name, start, end, data
        self.prg_off, self.file_off, self.note = prg_off, file_off, note
        self._labeler = labeler

    def contains(self, addr):
        return self.start <= addr < self.end

    def byte(self, addr):
        return self.data[addr - self.start]

    def offset_of(self, addr):
        """(prg offset, file offset) of a CPU address inside this block."""
        return self.prg_off + (addr - self.start), self.file_off + (addr - self.start)

    def label(self, addr):
        """`block:addr` text for a CPU address: this block if it lies in it, else the window
        that holds it in the home layout, else a bare address."""
        if self.contains(addr):
            return '%s:%04x' % (self.name, addr)
        return self._labeler(addr) if self._labeler else '?:%04x' % addr


# ---------------------------------------------------------------- expression (DescriptorExpressions)

_TOK = re.compile(r'\s*(0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|>>|[-+*()])')


def eval_expr(expr, image_size, window_size, env):
    """Same grammar as DescriptorExpressions.evalExpr: + - over (* >>) chains, parentheses,
    last/second_last/image_size, state-field names from env."""
    toks, pos = [], 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOK.match(expr, pos)
        if not m:
            raise BlockError("cannot parse maps expression '%s'" % expr)
        toks.append(m.group(1))
        pos = m.end()
    i = [0]

    def peek():
        return toks[i[0]] if i[0] < len(toks) else None

    def factor():
        t = peek()
        i[0] += 1
        if t == '(':
            v = total()
            if peek() != ')':
                raise BlockError("unbalanced parentheses in '%s'" % expr)
            i[0] += 1
            return v
        if t is None:
            raise BlockError("truncated expression '%s'" % expr)
        if t[0].isdigit():
            return int(t, 0)
        if t == 'last':
            return image_size - window_size
        if t == 'second_last':
            return image_size - 2 * window_size
        if t == 'image_size':
            return image_size
        if t in env:
            return env[t]
        raise BlockError("expression '%s' needs unbound name '%s'" % (expr, t))

    def product():
        v = factor()
        while peek() in ('*', '>>'):
            op = toks[i[0]]
            i[0] += 1
            r = factor()
            v = v * r if op == '*' else v >> r
        return v

    def total():
        v = product()
        while peek() in ('+', '-'):
            op = toks[i[0]]
            i[0] += 1
            r = product()
            v = v + r if op == '+' else v - r
        return v

    v = total()
    if i[0] != len(toks):
        raise BlockError("trailing text in expression '%s'" % expr)
    return v


def referenced_fields(expr):
    return {t for t in re.findall(r'(?<!\w)[A-Za-z_]\w*', expr)
            if t not in ('last', 'second_last', 'image_size')}


def decoded_mask(expr, window_size, field, width):
    """Bits of `field` the expression actually decodes (DescriptorExpressions.decodedMask)."""
    full = (1 << width) - 1
    if width > 16:
        return full
    try:
        vals = [eval_expr(expr, 1 << 40, window_size, {field: v}) for v in range(full + 1)]
    except BlockError:
        return full
    mask = 0
    for b in range(width):
        for v in range(full + 1):
            if not v & (1 << b) and vals[v] != vals[v | (1 << b)]:
                mask |= 1 << b
                break
    return mask


# ---------------------------------------------------------------- NES board model

def _yaml():
    try:
        import yaml
    except ImportError:
        raise BlockError('PyYAML is required to read machines/*.yaml (pip install pyyaml)') from None
    return yaml


def _load_descriptor(board_id):
    yaml = _yaml()
    mdir = os.path.join(ROOT, 'machines')
    for fn in sorted(os.listdir(mdir)):
        if fn.endswith('.yaml'):
            with open(os.path.join(mdir, fn), encoding='utf-8') as f:
                doc = yaml.safe_load(f)
            if isinstance(doc, dict) and (doc.get('system') or {}).get('id') == board_id:
                return doc
    raise BlockError("no machines/*.yaml descriptor with system.id '%s'" % board_id)


def _game_state(board_id, prg_sha):
    """banking.initial_state from the machines/games/*.yaml pinned to this PRG, else {}."""
    yaml = _yaml()
    gdir = os.path.join(ROOT, 'machines', 'games')
    if not os.path.isdir(gdir):
        return {}
    for fn in sorted(os.listdir(gdir)):
        if not fn.endswith('.yaml'):
            continue
        with open(os.path.join(gdir, fn), encoding='utf-8') as f:
            doc = yaml.safe_load(f)
        g = (doc or {}).get('game') or {}
        if g.get('board') == board_id and (g.get('identity') or {}).get('prg_sha256') == prg_sha:
            return dict(((doc.get('banking') or {}).get('initial_state')) or {})
    return {}


class NesBoard:
    def __init__(self, board_id, prg, prg_file_off, prg_sha):
        d = _load_descriptor(board_id)
        self.id, self.prg, self.prg_file_off = board_id, prg, prg_file_off
        banking = d.get('banking') or {}
        self.fields = {s['name']: s['bits'] for s in banking.get('state') or []}
        state = dict(banking.get('initial_state') or {})
        state.update(_game_state(board_id, prg_sha))
        self.state = {}
        for k, v in state.items():
            self.state[k] = v if isinstance(v, int) else eval_expr(str(v), len(prg), 0, {})
        self.win = {}      # name -> [(mode|None, start, size, expr)]
        self.mode_field = None
        mem = d.get('memory') or {}
        for w in mem.get('windows') or []:
            self._add(None, w)
        for lay in mem.get('layouts') or []:
            (mf, mv), = lay['when'].items()
            self.mode_field = mf
            for w in lay['windows']:
                self._add(mv, w)
        self.home_mode = self.state.get(self.mode_field) if self.mode_field else None
        self.mode_inferred = False

    def _add(self, mode, w):
        if 'maps' not in w:
            return
        m = re.fullmatch(r'PRG\[(.*)\]', str(w['maps']).strip())
        if not m:
            return
        size = w['size'] if 'size' in w else w['end'] - w['start'] + 1
        self.win.setdefault(w['name'], []).append((mode, w['start'], size, m.group(1)))

    # -- name parsing
    def _split(self, block):
        for name in sorted(self.win, key=len, reverse=True):
            if block == name or block.startswith(name + '_'):
                m = re.fullmatch(r'(?:_M(\d+))?(?:_B(\d+))?', block[len(name):])
                if m:
                    mode = int(m.group(1)) if m.group(1) else None
                    bank = int(m.group(2)) if m.group(2) else None
                    return name, mode, bank
        raise BlockError("'%s' is not a PRG window block of board %s; windows: %s"
                         % (block, self.id, ', '.join(sorted(self.win)) or '(none)'))

    def _instance(self, name, mode, bank=None):
        insts = self.win[name]
        if mode is None:
            if len(insts) == 1 or all(i[1:] == insts[0][1:] for i in insts):
                return insts[0]
            home = [i for i in insts if i[0] == self.home_mode]
            sw = [i for i in insts if referenced_fields(i[3])]
            if bank is not None and not (home and referenced_fields(home[0][3])):
                # _B<n> only exists for a switchable instance; the loader's image-scanned layout
                # mode (scanImageMode) can make the non-initial mode the live one (tmnt3: WC000_B).
                if len(sw) == 1:
                    return sw[0]
                raise BlockError("%s_B%d: ambiguous, several layout modes make %s switchable; "
                                 "name one (%s_M<m>_B%d)" % (name, bank, name, name, bank))
            if home:
                return home[0]
            raise BlockError("window %s has no instance in the home layout (%s=%s); name a mode "
                             "(%s_M<m>[_B<n>]), layouts: %s" % (
                                 name, self.mode_field, self.home_mode, name,
                                 sorted(i[0] for i in insts)))
        for i in insts:
            if i[0] == mode:
                return i
        raise BlockError("window %s has no layout instance for %s=%d (modes: %s)"
                         % (name, self.mode_field, mode, sorted(i[0] for i in insts)))

    def _offset(self, name, mode, bank):
        """(srcOffset, size, start, mirrored-flag) for a window instance."""
        _, start, size, expr = self._instance(name, mode, bank)
        fields = sorted(referenced_fields(expr))
        n = len(self.prg)
        if not fields:
            if bank is not None:
                raise BlockError("%s is a fixed window; it has no _B<n> instances" % name)
            return eval_expr(expr, n, size, {}), size, start
        if len(fields) != 1 or fields[0] not in self.fields:
            raise BlockError("%s: '%s' does not reference exactly one banking.state field"
                             % (name, expr))
        f = fields[0]
        mask = decoded_mask(expr, size, f, self.fields[f])
        if bank is None:
            bank = self.state.get(f, 0) & mask
        if bank >> self.fields[f]:
            raise BlockError("%s_B%d: %s is a %d-bit field, so %d is out of range"
                             % (name, bank, f, self.fields[f], bank))
        if bank & mask != bank:
            raise BlockError("%s_B%d: %s=%d is not a canonical value (loader names %d; the "
                             "expression ignores mask ~0x%x)" % (name, bank, f, bank, bank & mask,
                                                                 mask))
        return eval_expr(expr, n, size, {f: bank}), size, start

    def resolve(self, block):
        name, mode, bank = self._split(block)
        off, size, start = self._offset(name, mode, bank)
        n = len(self.prg)
        note = ''
        insts = self.win[name]
        if mode is None and not all(i[1:] == insts[0][1:] for i in insts):
            how = ('inferred from the golden block names' if self.mode_inferred else
                   'taken from initial_state/game hint; the loader may have image-scanned another')
            note = 'layout %s=%s %s' % (self.mode_field, self.home_mode, how) if bank is None else ''
        if 0 < n < size:                       # undecoded high lines: image mirrors to fill it
            if size % n or off % n:
                raise BlockError('%s: %d-byte image cannot mirror into a %d-byte window'
                                 % (block, n, size))
            data = (self.prg * (size // n))[:size]
            off, note = 0, (note + '; ' if note else '') + 'image mirrors %dx in this window' % (size // n)
        elif off < 0 or off + size > n:
            raise BlockError("%s: maps to PRG[%d..%d) outside the %d-byte image, so the loader "
                             "creates no such block" % (block, off, off + size, n))
        else:
            data = self.prg[off:off + size]
        return BlockView(block, start, start + size, data, off, self.prg_file_off + off,
                         self._label, note)

    def _label(self, addr):
        for name, insts in sorted(self.win.items()):
            for mode, start, size, expr in insts:
                if mode in (None, self.home_mode) and start <= addr < start + size:
                    sw = ' (bank-dependent)' if referenced_fields(expr) else ''
                    return '%s:%04x%s' % (name, addr, sw)
        return '?:%04x' % addr

    def infer_mode(self, golden_names):
        """The loader image-scans the live layout mode (NesRomLoader.scanImageMode), which a
        descriptor cannot predict. When the golden shows collapsed names (<w>_B<n>, no _M names),
        adopt the one layout mode whose switchable windows are exactly those; else keep the
        initial_state/hint mode."""
        if self.mode_field is None or any(re.search(r'_M\d', n) for n in golden_names):
            return
        banked = set()
        for n in golden_names:
            m = re.fullmatch(r'(.+)_B\d+', n)
            if m and m.group(1) in self.win:
                banked.add(m.group(1))
        if not banked:
            return
        fits = []
        for mode in sorted({i[0] for v in self.win.values() for i in v if i[0] is not None}):
            sw = {nm for nm, v in self.win.items()
                  if any(i[0] in (None, mode) and referenced_fields(i[3]) for i in v)}
            if sw == banked:
                fits.append(mode)
        if len(fits) == 1 and fits[0] != self.home_mode:
            self.home_mode = fits[0]
            self.mode_inferred = True

    def describe(self):
        """Human listing of every window and its naming (for --blocks)."""
        out = []
        for name in sorted(self.win, key=lambda k: self.win[k][0][1]):
            for mode, start, size, expr in self.win[name]:
                tag = '' if mode is None else ' [%s=%s]' % (self.mode_field, mode)
                try:
                    off, _, _ = self._offset(name, mode, None)
                    home = 'home: prg $%x' % off
                except BlockError as e:
                    home = 'home: n/a (%s)' % e
                out.append('%-8s %04x-%04x  PRG[%s]%s  %s' % (name, start, start + size - 1,
                                                            expr, tag, home))
        out.append('names: <w> (home) | <w>_B<n> | <w>_M<m> | <w>_M<m>_B<n>  (n = state field value)')
        return out


def resolve_nes(row, image_path, block):
    """row: manifest row fields (id,title,sha,mapper,board,...)."""
    board_id = row[4] if len(row) > 4 else '-'
    if not board_id.startswith('nes_'):
        raise BlockError("row %s has board '%s': no NES block mapping" % (row[0], board_id))
    ines = romlib.parse_ines(image_path)
    if ines is None:
        raise BlockError('%s is not an iNES image' % image_path)
    with open(image_path, 'rb') as f:
        flag6 = f.read(7)[6]
    prg = ines[1]
    board = NesBoard(board_id, prg, 16 + (512 if flag6 & 4 else 0),
                     hashlib.sha256(prg).hexdigest())
    golden = os.path.join(romlib.REALROM_DIR, 'expected', row[5]) if len(row) > 5 else ''
    names = set()
    if os.path.isfile(golden):
        with open(golden, encoding='utf-8') as f:
            names = set(re.findall(r'REALROM block (\S+) ', f.read()))
        board.infer_mode(names)
    if block is None:
        return board
    view = board.resolve(block)
    if names:
        if block not in names:
            print("warning: golden %s lists no block '%s' (the loader may not create it, or "
                  "its live layout mode differs): blocks are %s"
                  % (row[5], block, ' '.join(sorted(n for n in names if n[0] in 'PW'))),
                  file=sys.stderr)
    return view


RESOLVERS = {'nes': resolve_nes}


def platform_of(row):
    """Platform key for a manifest row (board column prefix); only 'nes' has a resolver."""
    board = row[4] if len(row) > 4 else '-'
    return board.split('_', 1)[0] if board != '-' else None


def find_row(row_id):
    for f in romlib.manifest_rows():
        if f[0] == row_id:
            return f
    raise BlockError('no manifest row ' + row_id)
