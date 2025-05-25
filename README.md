# jolokia

![Crates.io License](https://img.shields.io/crates/l/jolokia)
![GitHub Tag](https://img.shields.io/github/v/tag/qrichert/jolokia?sort=semver&filter=*.*.*&label=release)
[![tokei (loc)](https://tokei.rs/b1/github/qrichert/jolokia?label=loc&style=flat)](https://github.com/XAMPPRocky/tokei)
[![crates.io](https://img.shields.io/crates/d/jolokia?logo=rust&logoColor=white&color=orange)](https://crates.io/crates/jolokia)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/qrichert/jolokia/ci.yml?label=tests)](https://github.com/qrichert/jolokia/actions)

_Encrypt and decrypt stuff._

## Roadman

- [ ] `genkey`
- [ ] `encrypt`
- [ ] `decrypt`
  - [ ] From CLI argument.
  - [ ] From `stdin`.
  - [ ] From file.
  - [ ] From directory.
- [ ] `--help`
- [ ] `--algorithm`

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
