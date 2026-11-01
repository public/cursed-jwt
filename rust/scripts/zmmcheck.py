#!/usr/bin/env python3
"""zmmcheck.py ASM: per engine function of the x86-64 assembly listing, count zmm / ymm instructions.
Fails if any function other than the zmm engine touches a zmm register (a frequency-licence drop on Intel)."""

import re
import sys

fn, stats = None, {}
for l in open(sys.argv[1]):
    m = re.match(r"^(_?[A-Za-z0-9_$.]+):\s*$", l)
    if m and not l.startswith(".L"):
        fn = m.group(1)
        continue
    if l.lstrip().startswith("."):
        continue
    if fn and "cursed_jwt" in fn:
        st = stats.setdefault(fn, [0, 0])
        st[0] += "%zmm" in l
        st[1] += "%ymm" in l
bad = 0
for f, (z, y) in sorted(stats.items()):
    if z or y:
        name = re.sub(r"^_RNv.*?cursed_jwt", "", f)
        ok = z == 0 or "zmm" in name
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} zmm {z:5} ymm {y:6}  {name[-70:]}")
sys.exit(1 if bad else 0)
