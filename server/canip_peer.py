#!/usr/bin/env python3
"""
canip_peer.py — v4.1 (legacy v4.0 compatible)

What’s new vs your v4.0:
- v4.1 feature negotiation via a one-line hello (SEQ default ON, TS opt-in).
- Fixed-size frames (no length prefix), preserving your lean framing:
    * v4.0 legacy           : 14 bytes/frame
    * v4.1 FEAT=SEQ         : 18 bytes/frame (adds 4-byte seq, big-endian)
    * v4.1 FEAT=SEQ,TS      : 26 bytes/frame (adds 4 seq + 8 ts, big-endian)
- Menu retained: h, q, v0..v3, s on/off, pf/bf/r/pl, kc/ka/kb, t.
- New menu command: st  → shows negotiated link status (features, frame size).
- Clean quit (no Task exception spam).

Classic CAN payload (8B) on the wire for simplicity. CAN FD on the CAN side is allowed
(--can-fd), but TCP framing remains 8B payload here.

(c) CAN over IP
"""

from __future__ import annotations
import argparse
import asyncio
import contextlib
import dataclasses
import logging
import os
import re
import sys
import time
from typing import Iterable, List, Optional, Tuple

try:
    import can  # python-can
except ImportError as e:
    print("python-can is required. pip install python-can", file=sys.stderr)
    raise

# ==========================
# Constants & simple helpers
# ==========================
# v4.0 legacy fixed frame:
FIXED_FRAME_BYTES_V40 = 14  # [flags(1)][dlc(1)][can_id(4 LE)][data(8)]
FLAGS_EXTENDED = 0x01

STD_MAX_ID = 0x7FF
EXT_MAX_ID = 0x1FFFFFFF

MAX_KERNEL_FILTERS = 512  # practical limit; drivers/adapters may support fewer

VERBOSITY_LEVELS = {
    0: logging.ERROR,
    1: logging.WARNING,
    2: logging.INFO,
    3: logging.DEBUG,
}

# ==========================
# v4.1 feature negotiation
# ==========================
FEAT_SEQ = 0x01
FEAT_TS  = 0x02

HELLO_PREFIX = b"CANIP/4.1"
HELLO_EOL    = b"\n"

def make_hello_line(features: int) -> bytes:
    feats = []
    if features & FEAT_SEQ: feats.append("SEQ")
    if features & FEAT_TS:  feats.append("TS")
    if feats:
        return HELLO_PREFIX + b" FEAT=" + ",".join(feats).encode() + HELLO_EOL
    else:
        return HELLO_PREFIX + HELLO_EOL

def parse_hello_line(line: bytes) -> Optional[int]:
    """
    Returns features bitmask, or None if not a v4.1 hello (legacy peer).
    """
    try:
        line = line.rstrip(b"\r\n")
        if not line.startswith(HELLO_PREFIX):
            return None  # legacy
        parts = line.decode(errors="ignore").split()
        feats = 0
        for p in parts[1:]:
            if p.startswith("FEAT="):
                for tag in p.split("=", 1)[1].split(","):
                    tag = tag.strip().upper()
                    if tag == "SEQ": feats |= FEAT_SEQ
                    elif tag == "TS": feats |= FEAT_TS
        return feats
    except Exception:
        return None

async def do_handshake(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter,
                       local_features: int,
                       timeout: float = 2.0) -> int:
    """
    Negotiate features. Returns agreed_features (bitmask).
    - If peer is legacy: returns 0 (legacy v4.0 mode).
    - Otherwise returns intersection of features.
    """
    try:
        writer.write(make_hello_line(local_features))
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return 0  # legacy
        peer_features = parse_hello_line(line)
        if peer_features is None:
            return 0  # legacy
        return (local_features & peer_features)
    except Exception:
        return 0

def frame_size_from_features(agreed_features: int) -> int:
    # Base is 14; add seq(4) and optionally ts(8)
    size = FIXED_FRAME_BYTES_V40
    if agreed_features & FEAT_SEQ:
        size += 4
    if agreed_features & FEAT_TS:
        size += 8
    return size

# ==================
# Filter definitions
# ==================
@dataclasses.dataclass
class IdRange:
    start: int
    end: int
    extended: bool = False
    def contains(self, cid: int, ext: bool) -> bool:
        if ext != self.extended:
            return False
        return self.start <= cid <= self.end

@dataclasses.dataclass
class IdMask:
    can_id: int
    can_mask: int
    extended: bool = False
    def matches(self, cid: int, ext: bool) -> bool:
        if ext != self.extended:
            return False
        return (cid & self.can_mask) == (self.can_id & self.can_mask)

@dataclasses.dataclass
class ScriptFilter:
    """Fast in-process allow/block matcher."""
    allow_ids_std: set[int]
    allow_ids_ext: set[int]
    allow_ranges: List[IdRange]
    allow_masks: List[IdMask]
    block_ids_std: set[int]
    block_ids_ext: set[int]
    block_ranges: List[IdRange]
    block_masks: List[IdMask]
    enabled: bool = True

    def matches(self, cid: int, extended: bool) -> bool:
        if not self.enabled:
            return True
        allow_hit = True
        have_allow = bool(self.allow_ids_std or self.allow_ids_ext or self.allow_ranges or self.allow_masks)
        if have_allow:
            allow_hit = (
                (cid in (self.allow_ids_ext if extended else self.allow_ids_std)) or
                any(r.contains(cid, extended) for r in self.allow_ranges) or
                any(m.matches(cid, extended) for m in self.allow_masks)
            )
        block_hit = (
            (cid in (self.block_ids_ext if extended else self.block_ids_std)) or
            any(r.contains(cid, extended) for r in self.block_ranges) or
            any(m.matches(cid, extended) for m in self.block_masks)
        )
        return allow_hit and not block_hit

    @classmethod
    def empty(cls) -> "ScriptFilter":
        return cls(set(), set(), [], [], set(), set(), [], [], enabled=True)

# =====================
# Filter file utilities
# =====================
_TOKEN_RE = re.compile(r"\s*,\s*|\s+")

def _parse_token(tok: str) -> Tuple[str, ...]:
    """Return a normalized token tuple describing a clause."""
    tok = tok.strip()
    if not tok or tok.startswith('#'):
        return ()
    if '-' in tok:
        a, b = tok.split('-', 1)
        ax = a.lower().endswith('x')
        bx = b.lower().endswith('x')
        ext = ax or bx
        a = a[:-1] if ax else a
        b = b[:-1] if bx else b
        sa = int(a, 0)
        sb = int(b, 0)
        return ('range', sa, sb, ext)
    if '/' in tok:
        i, m = tok.split('/', 1)
        ix = i.lower().endswith('x')
        i = i[:-1] if ix else i
        return ('mask', int(i, 0), int(m, 0), ix)
    is_ext = tok.lower().endswith('x')
    if is_ext:
        tok = tok[:-1]
    return ('id', int(tok, 0), is_ext)

def load_filter_file(path: str) -> Tuple[List[Tuple[str, ...]], List[str]]:
    raw = []
    warnings: List[str] = []
    if not path:
        return raw, ["Empty path"]
    if not os.path.isfile(path):
        return raw, [f"Filter file not found: {path}"]
    with open(path, 'r', encoding='utf-8') as f:
        data = f.read()
    for token in filter(None, _TOKEN_RE.split(data)):
        try:
            t = _parse_token(token)
            if t:
                raw.append(t)
        except Exception as e:
            warnings.append(f"Ignoring token '{token}': {e}")
    return raw, warnings

def compile_script_filter(pass_tokens: List[Tuple[str, ...]], block_tokens: List[Tuple[str, ...]]) -> ScriptFilter:
    sf = ScriptFilter.empty()
    def add(tok: Tuple[str, ...], allow: bool):
        kind = tok[0]
        if kind == 'id':
            _, cid, ext = tok
            (sf.allow_ids_ext if allow and ext else sf.allow_ids_std if allow else sf.block_ids_ext if ext else sf.block_ids_std).add(cid)
        elif kind == 'range':
            _, a, b, ext = tok
            r = IdRange(min(a, b), max(a, b), ext)
            (sf.allow_ranges if allow else sf.block_ranges).append(r)
        elif kind == 'mask':
            _, cid, cmask, ext = tok
            m = IdMask(cid, cmask, ext)
            (sf.allow_masks if allow else sf.block_masks).append(m)
    for t in pass_tokens:  add(t, True)
    for t in block_tokens: add(t, False)
    return sf

def tokens_to_kernel_filters(tokens: List[Tuple[str, ...]]) -> Tuple[List[dict], List[str]]:
    """Convert tokens to python-can filter dicts."""
    filters: List[dict] = []
    warnings: List[str] = []
    def add_filter(can_id: int, can_mask: int, extended: bool):
        filters.append({'can_id': can_id, 'can_mask': can_mask, 'extended': extended})
    def try_range(a: int, b: int, ext: bool):
        start = a
        remaining = b - a + 1
        while remaining > 0:
            chunk = 1
            while (start & ((chunk << 1) - 1)) == 0 and (chunk << 1) <= remaining:
                chunk <<= 1
            full_mask = (EXT_MAX_ID if ext else STD_MAX_ID)
            m = full_mask & (~((chunk - 1)))
            add_filter(start, m, ext)
            start += chunk
            remaining -= chunk
    for t in tokens:
        kind = t[0]
        if kind == 'id':
            _, cid, ext = t
            add_filter(cid, EXT_MAX_ID if ext else STD_MAX_ID, ext)
        elif kind == 'mask':
            _, cid, cmask, ext = t
            add_filter(cid, cmask, ext)
        elif kind == 'range':
            _, a, b, ext = t
            a, b = (a, b) if a <= b else (b, a)
            span = b - a + 1
            if span <= 64:
                full_mask = EXT_MAX_ID if ext else STD_MAX_ID
                for cid in range(a, b + 1):
                    add_filter(cid, full_mask, ext)
                    if len(filters) >= MAX_KERNEL_FILTERS:
                        warnings.append("Kernel filter budget exceeded while expanding range; truncating.")
                        return filters, warnings
            else:
                try_range(a, b, ext)
            if len(filters) >= MAX_KERNEL_FILTERS:
                warnings.append("Kernel filter budget exceeded; resulting set truncated.")
                break
    return filters[:MAX_KERNEL_FILTERS], warnings

# =====================
# Bridge core (asyncio)
# =====================
@dataclasses.dataclass
class Stats:
    rx_can: int = 0
    tx_can: int = 0
    rx_tcp: int = 0
    tx_tcp: int = 0
    dropped_script: int = 0
    last_report_ts: float = dataclasses.field(default_factory=time.time)
    def snapshot_and_reset_rate(self) -> str:
        now = time.time()
        dt = max(1e-6, now - self.last_report_ts)
        r = (f"CAN rx: {self.rx_can/dt:.1f}/s  tx: {self.tx_can/dt:.1f}/s | "
             f"TCP rx: {self.rx_tcp/dt:.1f}/s  tx: {self.tx_tcp/dt:.1f}/s | "
             f"dropped (script): {self.dropped_script/dt:.1f}/s")
        self.rx_can = self.tx_can = self.rx_tcp = self.tx_tcp = self.dropped_script = 0
        self.last_report_ts = now
        return r

class SeqTxState:
    def __init__(self):
        self.seq = 0
    def next(self) -> int:
        s = self.seq
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        return s

class SeqRxTracker:
    def __init__(self, name: str):
        self.name = name
        self.last = None
    def check(self, seq: int):
        if self.last is None:
            self.last = seq
            return
        expect = (self.last + 1) & 0xFFFFFFFF
        if seq != expect:
            gap = (seq - expect) & 0xFFFFFFFF
            if gap == 0xFFFFFFFF:
                logging.warning("[%s] SEQ duplicate: got 0x%08X", self.name, seq)
            else:
                logging.warning("[%s] SEQ gap: expected 0x%08X got 0x%08X (+%d)", self.name, expect, seq, gap)
        self.last = seq

class Bridge:
    """
    Holds shared items (bus, script filter, stats) and encoding helpers.
    """
    def __init__(self, bus: can.BusABC, sf: ScriptFilter, log: logging.Logger):
        self.bus = bus
        self.sf = sf
        self.log = log
        self.stats = Stats()

    # ============ TCP framing helpers ============
    @staticmethod
    def encode_frame_v40(msg: can.Message) -> bytes:
        flags = FLAGS_EXTENDED if msg.is_extended_id else 0
        dlc = min(msg.dlc, 8)
        cid = msg.arbitration_id & (EXT_MAX_ID if msg.is_extended_id else STD_MAX_ID)
        data = (msg.data + b"\x00" * 8)[:8]
        return bytes([flags, dlc]) + cid.to_bytes(4, 'little') + data

    @staticmethod
    def decode_frame_v40(buf: bytes) -> Tuple[int, bool, bytes]:
        if len(buf) != FIXED_FRAME_BYTES_V40:
            raise ValueError("bad v4.0 frame length")
        flags = buf[0]
        dlc = buf[1]
        ext = bool(flags & FLAGS_EXTENDED)
        cid = int.from_bytes(buf[2:6], 'little')
        data = buf[6:6+8][:dlc]
        return cid, ext, data

    @staticmethod
    def encode_frame_v41(msg: can.Message, agreed_features: int, seq_value: Optional[int], ts_us: Optional[int]) -> bytes:
        """
        v4.1 fixed-size per agreed features:
          base 14 + [seq? 4] + [ts? 8]
        """
        flags = FLAGS_EXTENDED if msg.is_extended_id else 0
        dlc = min(msg.dlc, 8)
        cid = msg.arbitration_id & (EXT_MAX_ID if msg.is_extended_id else STD_MAX_ID)
        data = (msg.data + b"\x00" * 8)[:8]

        out = bytearray()
        out += bytes([flags, dlc])
        out += cid.to_bytes(4, 'little')
        out += data
        if agreed_features & FEAT_SEQ:
            if seq_value is None:
                raise ValueError("SEQ negotiated but seq_value not provided")
            out += seq_value.to_bytes(4, 'big')
        if agreed_features & FEAT_TS:
            if ts_us is None:
                raise ValueError("TS negotiated but ts_us not provided")
            out += ts_us.to_bytes(8, 'big')
        return bytes(out)

    @staticmethod
    def decode_frame_v41(buf: bytes, agreed_features: int) -> Tuple[int, bool, bytes, Optional[int], Optional[int]]:
        want_len = frame_size_from_features(agreed_features)
        if len(buf) != want_len:
            raise ValueError(f"bad v4.1 frame length (got {len(buf)} want {want_len})")
        flags = buf[0]
        dlc = buf[1]
        ext = bool(flags & FLAGS_EXTENDED)
        cid = int.from_bytes(buf[2:6], 'little')
        data = buf[6:14][:dlc]
        off = 14
        seq = None
        ts  = None
        if agreed_features & FEAT_SEQ:
            seq = int.from_bytes(buf[off:off+4], 'big'); off += 4
        if agreed_features & FEAT_TS:
            ts  = int.from_bytes(buf[off:off+8], 'big'); off += 8
        return cid, ext, data, seq, ts

    # ============ CAN<->TCP tasks ============
    async def pump_can_to_tcp(self,
                              writer: asyncio.StreamWriter,
                              agreed_features: int,
                              legacy_mode: bool,
                              tx_state: Optional[SeqTxState]):
        loop = asyncio.get_running_loop()
        reader = can.AsyncBufferedReader()
        notifier = can.Notifier(self.bus, [reader], loop=loop)
        self.log.info("CAN→TCP pump started (legacy=%s feats=0x%02X)", legacy_mode, agreed_features)
        try:
            while True:
                msg = await reader.get_message()
                self.stats.rx_can += 1
                if not self.sf.matches(msg.arbitration_id, msg.is_extended_id):
                    self.stats.dropped_script += 1
                    continue
                try:
                    if legacy_mode:
                        frame = self.encode_frame_v40(msg)
                    else:
                        seq = tx_state.next() if (tx_state and (agreed_features & FEAT_SEQ)) else None
                        ts_us = int(time.time() * 1_000_000) if (agreed_features & FEAT_TS) else None
                        frame = self.encode_frame_v41(msg, agreed_features, seq, ts_us)
                    writer.write(frame)
                    await writer.drain()
                    self.stats.tx_tcp += 1
                except Exception as e:
                    self.log.warning("TCP write error: %s", e)
                    await asyncio.sleep(0.01)
        finally:
            notifier.stop()
            self.log.info("CAN→TCP pump stopped")

    async def pump_tcp_to_can(self,
                              reader: asyncio.StreamReader,
                              agreed_features: int,
                              legacy_mode: bool,
                              rx_tracker: Optional[SeqRxTracker]):
        self.log.info("TCP→CAN pump started (legacy=%s feats=0x%02X)", legacy_mode, agreed_features)
        frame_len = FIXED_FRAME_BYTES_V40 if legacy_mode else frame_size_from_features(agreed_features)
        try:
            while True:
                buf = await reader.readexactly(frame_len)
                self.stats.rx_tcp += 1
                try:
                    if legacy_mode:
                        cid, ext, data = self.decode_frame_v40(buf)
                        seq = None
                    else:
                        cid, ext, data, seq, _ts = self.decode_frame_v41(buf, agreed_features)
                        if (rx_tracker is not None) and (seq is not None):
                            rx_tracker.check(seq)
                except Exception as e:
                    self.log.debug("Frame decode error: %s", e)
                    continue

                if not self.sf.matches(cid, ext):
                    self.stats.dropped_script += 1
                    continue

                msg = can.Message(arbitration_id=cid, is_extended_id=ext, data=data)
                try:
                    self.bus.send(msg, timeout=0.0)
                    self.stats.tx_can += 1
                except can.CanError:
                    self.log.debug("CAN TX busy; frame dropped")
        except asyncio.IncompleteReadError:
            self.log.info("TCP peer closed")
        finally:
            self.log.info("TCP→CAN pump stopped")

# ==================
# Runtime UI (menu)
# ==================
class Menu:
    HELP_TEXT = (
        "\n"
        "Commands (type key + ENTER):\n"
        "  h            : help\n"
        "  q            : quit\n"
        "  v0|v1|v2|v3  : verbosity (0=ERROR,1=WARN,2=INFO,3=DEBUG)\n"
        "  s on|off     : enable/disable script filter\n"
        "  pf <file>    : set pass-filter file (allow-list)\n"
        "  bf <file>    : set block-filter file (deny-list)\n"
        "  r            : reload filter files\n"
        "  pl           : print current filter summary\n"
        "  kc           : clear kernel filters (accept-all)\n"
        "  ka           : apply kernel filters from pass-filter tokens\n"
        "  kb           : apply kernel filters from block-filter tokens (deny via driver; risky)\n"
        "  t            : show throughput since last t\n"
        "  st           : show negotiated link status (features, legacy, frame size)\n"
    )
    def __init__(self, bus: can.BusABC, log: logging.Logger, bridge: Bridge):
        self.bus = bus
        self.log = log
        self.bridge = bridge
        self.pass_tokens: List[Tuple[str, ...]] = []
        self.block_tokens: List[Tuple[str, ...]] = []
        self.pass_path: Optional[str] = None
        self.block_path: Optional[str] = None
        # link status
        self._legacy: Optional[bool] = None
        self._agreed: int = 0
        self._frame_len: int = 0

    def print(self, *a): print(*a, flush=True)

    def set_link_status(self, legacy: bool, agreed_features: int, frame_len: int):
        self._legacy = legacy
        self._agreed = agreed_features
        self._frame_len = frame_len

    def status_line(self) -> str:
        if self._legacy is None:
            return "Link: (not connected yet)"
        feats = []
        if self._agreed & FEAT_SEQ: feats.append("SEQ")
        if self._agreed & FEAT_TS:  feats.append("TS")
        mode = "v4.0-legacy" if self._legacy else ("v4.1" if feats else "v4.1 (no features)")
        feats_str = ",".join(feats) if feats else "none"
        return f"Link: {mode} | FEAT={feats_str} | frame_len={self._frame_len}B"

    def set_verbosity(self, lvl: int):
        lvl = max(0, min(3, lvl))
        logging.getLogger().setLevel(VERBOSITY_LEVELS[lvl])
        self.print(f"Verbosity set to v{lvl}")

    def _apply_script_filter(self):
        sf = compile_script_filter(self.pass_tokens, self.block_tokens)
        self.bridge.sf = sf
        self.print("Script filter updated.")

    def _load_file(self, kind: str, path: str):
        toks, warns = load_filter_file(path)
        for w in warns: self.print("[filter] ", w)
        if kind == 'pass':
            self.pass_tokens = toks; self.pass_path = path
        else:
            self.block_tokens = toks; self.block_path = path
        self._apply_script_filter()
        self.print(self.summary())

    def summary(self) -> str:
        sf = self.bridge.sf
        return ("Filter summary: "
                f"allow_ids_std={len(sf.allow_ids_std)} allow_ids_ext={len(sf.allow_ids_ext)} "
                f"allow_ranges={len(sf.allow_ranges)} allow_masks={len(sf.allow_masks)} | "
                f"block_ids_std={len(sf.block_ids_std)} block_ids_ext={len(sf.block_ids_ext)} "
                f"block_ranges={len(sf.block_ranges)} block_masks={len(sf.block_masks)} | "
                f"enabled={'on' if sf.enabled else 'off'}")

    def apply_kernel_from(self, source: str):
        tokens = self.pass_tokens if source == 'pass' else self.block_tokens
        filts, warns = tokens_to_kernel_filters(tokens)
        for w in warns: self.print("[kernel] ", w)
        try:
            self.bus.set_filters([])
            if filts:
                self.bus.set_filters(filts)
                self.print(f"Applied {len(filts)} kernel filters from {source} tokens.")
            else:
                self.print("No filters generated; kernel left in accept-all mode.")
        except Exception as e:
            self.print(f"Failed to apply kernel filters: {e}")

    def clear_kernel(self):
        try:
            self.bus.set_filters([])
            self.print("Kernel filters cleared (accept-all).")
        except Exception as e:
            self.print(f"Failed to clear kernel filters: {e}")

    async def repl(self):
        self.print(self.HELP_TEXT)
        self.print(self.status_line())
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line: 
                continue
            line = line.strip()
            if not line:
                continue
            if line == 'h':
                self.print(self.HELP_TEXT); self.print(self.status_line())
            elif line == 'q':
                self.print("Quitting…")
                return
            elif line.startswith('v') and len(line) == 2 and line[1].isdigit():
                self.set_verbosity(int(line[1]))
            elif line.startswith('s '):
                arg = line.split(None, 1)[1].lower()
                self.bridge.sf.enabled = (arg == 'on')
                self.print(self.summary())
            elif line.startswith('pf '):
                path = line.split(None, 1)[1]; self._load_file('pass', path)
            elif line.startswith('bf '):
                path = line.split(None, 1)[1]; self._load_file('block', path)
            elif line == 'r':
                if self.pass_path:  self._load_file('pass',  self.pass_path)
                if self.block_path: self._load_file('block', self.block_path)
            elif line == 'pl':
                self.print(self.summary()); self.print(self.status_line())
            elif line == 'kc':
                self.clear_kernel()
            elif line == 'ka':
                self.apply_kernel_from('pass')
            elif line == 'kb':
                self.apply_kernel_from('block')
            elif line == 't':
                self.print(self.bridge.stats.snapshot_and_reset_rate())
            elif line == 'st':
                self.print(self.status_line())
            else:
                self.print("Unknown command. 'h' for help.")

# =====================
# Server/client wiring
# =====================
async def _serve_one_connection_with_menu(reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter,
                                          args,
                                          bus: can.BusABC,
                                          bridge: Bridge,
                                          log: logging.Logger,
                                          menu: Menu):
    addr = writer.get_extra_info('peername')
    log.info(f"Client connected: {addr}")

    # Build local features (SEQ default ON unless --no-seq)
    local_features = FEAT_SEQ
    if args.no_seq:
        local_features &= ~FEAT_SEQ
    if args.timestamp:
        local_features |= FEAT_TS

    # Handshake
    agreed = await do_handshake(reader, writer, local_features)
    legacy = (agreed == 0)
    frame_len = FIXED_FRAME_BYTES_V40 if legacy else frame_size_from_features(agreed)

    if legacy:
        log.info("Using legacy v4.0 frames")
    else:
        feats = []
        if agreed & FEAT_SEQ: feats.append("SEQ")
        if agreed & FEAT_TS:  feats.append("TS")
        log.info("Using v4.1 frames, FEAT=%s", ",".join(feats) if feats else "none")

    # Update menu status and echo it
    menu.set_link_status(legacy, agreed, frame_len)
    log.info(menu.status_line())

    tx_state = SeqTxState() if (agreed & FEAT_SEQ) else None
    rx_tracker = SeqRxTracker("server-rx") if (agreed & FEAT_SEQ) else None

    try:
        await asyncio.gather(
            bridge.pump_can_to_tcp(writer, agreed, legacy, tx_state),
            bridge.pump_tcp_to_can(reader, agreed, legacy, rx_tracker),
        )
    finally:
        with contextlib.suppress(Exception):
            writer.close(); await writer.wait_closed()
        log.info(f"Client disconnected: {addr}")
        # Reset link status to a neutral disconnected state
        menu.set_link_status(True, 0, FIXED_FRAME_BYTES_V40)

async def run_server(bus: can.BusABC, bind: str, port: int, args, log: logging.Logger):
    bridge = Bridge(bus, ScriptFilter.empty(), log)
    menu = Menu(bus, log, bridge)

    server = await asyncio.start_server(
        lambda r, w: _serve_one_connection_with_menu(r, w, args, bus, bridge, log, menu),
        bind, port
    )
    sockets = ', '.join(str(s.getsockname()) for s in server.sockets)
    log.info(f"Server listening on {sockets}")

    # Wait for either menu or server to finish, cancel the other.
    menu_task = asyncio.create_task(menu.repl())
    srv_task  = asyncio.create_task(server.serve_forever())
    done, pending = await asyncio.wait({menu_task, srv_task}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    with contextlib.suppress(Exception):
        await asyncio.gather(*pending, return_exceptions=True)

async def run_client(bus: can.BusABC, host: str, port: int, args, log: logging.Logger):
    bridge = Bridge(bus, ScriptFilter.empty(), log)
    menu = Menu(bus, log, bridge)

    async def connect_once():
        log.info(f"Connecting to {host}:{port}…")
        reader, writer = await asyncio.open_connection(host, port)
        log.info("Connected.")

        # Build local features (SEQ default ON unless --no-seq)
        local_features = FEAT_SEQ
        if args.no_seq:
            local_features &= ~FEAT_SEQ
        if args.timestamp:
            local_features |= FEAT_TS

        agreed = await do_handshake(reader, writer, local_features)
        legacy = (agreed == 0)
        frame_len = FIXED_FRAME_BYTES_V40 if legacy else frame_size_from_features(agreed)

        if legacy:
            log.info("Using legacy v4.0 frames")
        else:
            feats = []
            if agreed & FEAT_SEQ: feats.append("SEQ")
            if agreed & FEAT_TS:  feats.append("TS")
            log.info("Using v4.1 frames, FEAT=%s", ",".join(feats) if feats else "none")

        # Update & echo status
        menu.set_link_status(legacy, agreed, frame_len)
        log.info(menu.status_line())

        tx_state = SeqTxState() if (agreed & FEAT_SEQ) else None
        rx_tracker = SeqRxTracker("client-rx") if (agreed & FEAT_SEQ) else None

        try:
            await asyncio.gather(
                bridge.pump_can_to_tcp(writer, agreed, legacy, tx_state),
                bridge.pump_tcp_to_can(reader, agreed, legacy, rx_tracker),
            )
        finally:
            with contextlib.suppress(Exception):
                writer.close(); await writer.wait_closed()
            log.info("Disconnected.")
            # Reset status to disconnected
            menu.set_link_status(True, 0, FIXED_FRAME_BYTES_V40)

    # Outer loop: quit if menu exits; otherwise reconnect on errors.
    while True:
        menu_task = asyncio.create_task(menu.repl())
        conn_task = asyncio.create_task(connect_once())
        done, pending = await asyncio.wait({menu_task, conn_task}, return_when=asyncio.FIRST_COMPLETED)

        # If the menu ended (q), stop fully.
        if menu_task in done:
            for t in pending: t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*pending, return_exceptions=True)
            break

        # Otherwise the connection ended (disconnect/retry path):
        for t in pending: t.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(2.0)

# ==============
# Bus creation
# ==============
def make_bus(args) -> can.BusABC:
    kwargs = {
        'interface': args.can_interface,
        'channel': args.can,
    }
    if args.can_bitrate:
        kwargs['bitrate'] = args.can_bitrate
    if args.can_fd:
        kwargs['fd'] = True
        if args.data_bitrate:
            kwargs['data_bitrate'] = args.data_bitrate
    logging.getLogger('can').debug(f"can config: {kwargs}")
    return can.Bus(**kwargs)

# ==============
# CLI & main
# ==============
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CAN over IP peer — v4.1 (legacy v4.0 compatible)")
    sub = p.add_subparsers(dest='mode', required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--can', required=True, help='CAN channel (e.g., can0, vcan0)')
    common.add_argument('--can-interface', default='socketcan', help='python-can interface (default: socketcan)')
    common.add_argument('--can-bitrate', type=int, help='Classic CAN bitrate (e.g., 500000)')
    common.add_argument('--can-fd', action='store_true', help='Enable CAN FD on the CAN interface')
    common.add_argument('--data-bitrate', type=int, help='CAN FD data-phase bitrate (if supported)')

    common.add_argument('--log-level', default='INFO', choices=['ERROR','WARNING','INFO','DEBUG'])

    # feature toggles (SEQ default ON unless explicitly disabled)
    common.add_argument('--no-seq', action='store_true',
        help='Disable sequence numbers (default is enabled when both peers are v4.1)')
    common.add_argument('--timestamp', action='store_true',
        help='Enable microsecond timestamps (negotiated in v4.1)')

    # server
    sp = sub.add_parser('server', parents=[common])
    sp.add_argument('--bind', default='0.0.0.0')
    sp.add_argument('--port', type=int, default=3333)

    # client
    cp = sub.add_parser('client', parents=[common])
    cp.add_argument('--host', required=True)
    cp.add_argument('--port', type=int, default=3333)

    return p

def setup_logging(level: str):
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )

async def amain():
    args = build_argparser().parse_args()
    setup_logging(args.log_level)
    log = logging.getLogger('canip')
    log.info("Starting v4.1 (SEQ default ON; disable with --no-seq) TS=%s", bool(args.timestamp))
    bus = make_bus(args)
    try:
        if args.mode == 'server':
            await run_server(bus, args.bind, args.port, args, log)
        else:
            await run_client(bus, args.host, args.port, args, log)
    finally:
        with contextlib.suppress(Exception):
            bus.shutdown()

def main():
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")

if __name__ == '__main__':
    main()
