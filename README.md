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
hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=

$ jolokia encrypt "hello, world!" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=
l/wW9dop4IvF5fR6aRa7WkZKsRnUwG177Q35ej9WMVzhJYr0t8njDi0=

# Same as passing `--key`.
$ export JOLOKIA_CIPHER_KEY=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=

$ jolokia decrypt l/wW9dop4IvF5fR6aRa7WkZKsRnUwG177Q35ej9WMVzhJYr0t8njDi0=
hello, world!

# The key can be stored inside a file as well.
$ jolokia decrypt --key /secrets/jolokia.key l/wW9dop4IvF5fR6aRa7WkZKsRnUwG177Q35ej9WMVzhJYr0t8njDi0=
hello, world!
```

## Roadmap

- [x] `genkey`
- [x] `encrypt`/`decrypt`
  - [x] From CLI argument.
  - [x] From `stdin`.
  - [ ] From file (show example with `tar`).
  - [ ] From directory (`-R`, `--recursive`).
- [ ] `--help`
- [ ] `--raw` (for non-text files).
- [ ] Streaming encryption (will likely break existing messages!).
- [ ] Choose `--algorithm` (`JOLOKIA_ALGORITHM`).
  - [x] Chacha20-Poly1305
  - [ ] ROT13 (useless, but forces generic design).

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
