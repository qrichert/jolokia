# jolokia

![Crates.io License](https://img.shields.io/crates/l/jolokia)
![GitHub Tag](https://img.shields.io/github/v/tag/qrichert/jolokia?sort=semver&filter=*.*.*&label=release)
[![tokei (loc)](https://tokei.rs/b1/github/qrichert/jolokia?label=loc&style=flat)](https://github.com/XAMPPRocky/tokei)
[![crates.io](https://img.shields.io/crates/d/jolokia?logo=rust&logoColor=white&color=orange)](https://crates.io/crates/jolokia)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/qrichert/jolokia/ci.yml?label=tests)](https://github.com/qrichert/jolokia/actions)

_Strong encryption, made simple._

## Examples

```console
$ jolokia genkey
hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w

$ jolokia encrypt "hello, world!" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
Q0gyMAGnAk2xt/+cAAAAHYUv/WBO+VxMGHodIL0Qzjbtnv/LPpQd3CCcYW0kAAAAAA

# Same as passing `--key`.
$ export JOLOKIA_CIPHER_KEY=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w

$ jolokia decrypt Q0gyMAGnAk2xt/+cAAAAHYUv/WBO+VxMGHodIL0Qzjbtnv/LPpQd3CCcYW0kAAAAAA
hello, world!

# The key can be stored inside a file as well.
$ jolokia decrypt --key /secrets/jolokia.key Q0gyMAGnAk2xt/+cAAAAHYUv/WBO+VxMGHodIL0Qzjbtnv/LPpQd3CCcYW0kAAAAAA
hello, world!
```

## Roadmap

- [x] `genkey`
- [x] `encrypt`/`decrypt`
  - [x] From CLI argument.
  - [x] From `stdin`.
  - [x] From file (show example with `tar`).
  - [ ] From directory (`-R`, `--recursive`).
- [ ] Complete `--help`.
- [ ] `--raw` (for non-text files). Or should it be `--plain`?
- [x] Streaming cipher (everything is ready for it, CLI and algos, the
      two are just not yet connected).
- [ ] Choose `--algorithm` (`JOLOKIA_ALGORITHM`).
  - [x] Chacha20-Poly1305
  - [ ] ROT13 (useless, but forces generic design).
- [ ] If multiple algorithms, should we keep `JOLOKIA_CIPHER_KEY` as
      default also support specialized:
      `JOLOKIA_CIPHER_KEY_CHACHA20POLY1305`?). If so, rename
      `JOLOKIA_CIPHER_KEY` to just `JOLOKIA_KEY`.
- [ ] Zeroize secrets.
- [ ] Compression (Compress → Encrypt → Base64). Encryption produces a
      high entropy output that is unsuited for compression. So
      compression must come first in the pipeline. Use
      [`flate2`](https://docs.rs/flate2/latest/flate2/) with
      `rust_backend`.
- [ ] Support in-place ciphering (with a temporary intermediate file).

## Installation

### Directly

```console
$ wget https://github.com/qrichert/jolokia/releases/download/X.X.X/jolokia-X.X.X-xxx
$ sudo install ./jolokia-* /usr/local/bin/jolokia
```

### Manual Build

#### System-wide

```console
$ git clone https://github.com/qrichert/jolokia.git
$ cd jolokia
$ make build
$ sudo make install
```

#### Through Cargo

```shell
cargo install jolokia
cargo install --git https://github.com/qrichert/jolokia.git
```
