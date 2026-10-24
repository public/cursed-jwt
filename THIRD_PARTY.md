# Third-party credits

cursed-jwt contains no vendored third-party code. It credits these projects for techniques and data:

- **simdjson** (https://github.com/simdjson/simdjson, dual-licensed Apache-2.0 / MIT, Copyright 2018-2025 The
  simdjson authors). The opt-in `-DJWT_FAST_JSON` payload path in `src/jwt.c` follows simdjson's stage-1 design:
  the 16-entry operator/whitespace shuffle tables, the prefix-XOR quote mask (carry-less multiply on x86) and the
  bitmask "flatten" loop. Used under the MIT option:

  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
  > documentation files (the "Software"), to deal in the Software without restriction, including without
  > limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
  > Software, and to permit persons to whom the Software is furnished to do so, subject to the following
  > conditions: The above copyright notice and this permission notice shall be included in all copies or
  > substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

- **cpuminer-opt** (https://github.com/JayDDee/cpuminer-opt): the idea of reusing the previous round's
  `a ^ b` in SHA-256's Maj, saving two vector ops per round. No code is copied.
- **Intel isa-l_crypto** and **OpenSSL's sha256-mb**: the multi-buffer SHA-256 lane layout is the classic
  design these established; the `vpternlogd` immediates (0x96, 0xCA, 0xE8) are the standard truth tables. No
  code is copied.

Test and benchmark dependencies (not distributed): **OpenSSL** libcrypto (Apache-2.0) is the reference HMAC in
`tests/` and the baseline in `bench/`; the library itself does not use it.
