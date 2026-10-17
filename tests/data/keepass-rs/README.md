# keepass-rs test databases

These files are copied unchanged from the `tests/resources` folder of
[keepass-rs](https://github.com/sseemayer/keepass-rs) at commit `28c078c`.
They were written by KeePassXC, KeePass 2 and keepass-rs, and are used by
`tests/keepass_rs_fixtures.rs` to check that keepassxcr opens and saves files
from other tools.

Passwords: `demopass` unless listed below. Key files sit next to the
databases that use them.

| File | Credentials |
|---|---|
| `test_db_with_keyfile.kdbx`, `test_db_kdbx4_with_keyfile.kdbx` | key file `test_key.key` only |
| `test_db_with_keyfile_xml.kdbx` | key file `test_key_xml.key` only |
| `test_db_kdbx4_with_keyfile_v2*.kdbx` | `demopass` plus the `.keyx` file of the same name |
| `test_db_kdbx3_with_chacha20_protected_fields.kdbx` | `password` |
| `test_db_kdbx4_with_totp*.kdbx` | `test` |
| `test_db_with_challenge_response_key.kdbx` | `demopass` plus a YubiKey HMAC-SHA1 slot with secret `0102030405060708090a0b0c0d0e0f1011121314`; used by `tests/yubikey.rs` and `tests/test_yubikey_compat.py` |
| `broken_*.kdbx` | damaged on purpose; must fail to open |

License of these files:

```
MIT License

Copyright (c) 2019 Stefan Seemayer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
