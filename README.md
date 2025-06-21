# jolokia

![Crates.io License](https://img.shields.io/crates/l/jolokia)
![GitHub Tag](https://img.shields.io/github/v/tag/qrichert/jolokia?sort=semver&filter=*.*.*&label=release)
[![tokei (loc)](https://tokei.rs/b1/github/qrichert/jolokia?label=loc&style=flat)](https://github.com/XAMPPRocky/tokei)
[![crates.io](https://img.shields.io/crates/d/jolokia?logo=rust&logoColor=white&color=orange)](https://crates.io/crates/jolokia)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/qrichert/jolokia/ci.yml?label=tests)](https://github.com/qrichert/jolokia/actions)

_Simple, strong encryption._

## Examples

```console
$ jolokia keygen
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

## Get `--help`

```
Simple, strong encryption.

Usage: jolokia [<options>] <command> [<args>]

Commands:
  keygen                 Generate cipher key
  encrypt                Encrypt plaintext
  decrypt                Decrypt ciphertext

Args:
  <MESSAGE>
  -k, --key <KEY>        Cipher key (base64)
  -r, --raw              Handle message as raw binary
  -f, --file <FILE>      Read message from file
    -i, --in-place       Write output to input file
  -o, --output <FILE>    Write output to file

Options:
  -h, --help             Show help message and exit
  -V, --version          Show the version and exit
```

### What does jolokia do?

jolokia provides strong, modern, hard-to-misuse encryption for the
general public.

> [!WARNING]
>
> jolokia has not been audited for security. It is based on audited
> dependencies for the underlying algorithm implementations, but the
> final package (what you're using) was not.

> [!CAUTION]
>
> Do not encrypt data you can't afford to lose. Be especially cautious
> of in-place encryption; always make a backup first. If you lose your
> key, or if there's a bug, **YOUR DATA WILL NOT BE RECOVERABLE**.

### Algorithms

| Name              | Key Size            | Type       |
| ----------------- | ------------------- | ---------- |
| ChaCha20-Poly1305 | 32-bytes (256-bits) | Symmetric  |
| HPKE              | 32-bytes (256-bits) | Asymmetric |
| ROT-n             | 0..255 (insecure)   | Symmetric  |

### Key

In jolokia, a key is always a base64-encoded string of bytes. The size
of the key varies depending on the selected algorithm.

To generate a new key run:

```console
$ jolokia keygen
hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
```

To use the key, pass it as `--key` or `-k`:

```console
$ jolokia encrypt "foo" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA
```

Or as an environment variable (but `--key` has precedence):

```console
$ export JOLOKIA_CIPHER_KEY=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
$ jolokia encrypt "foo"
Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA
```

The key can also be the name of a file that contains a key:

```console
$ echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > /secrets/jolokia.key
$ jolokia decrypt --key /secrets/jolokia.key Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA
foo
```

To set a key permanently, the recommended solution is to point the
environment variable to a file:

```console
$ echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > ~/.jolokia.key
$ echo 'export JOLOKIA_CIPHER_KEY="$HOME/.jolokia.key"' >> ~/.bashrc
```

### Message

The message can be passed on the command line:

```console
$ jolokia encrypt "bar"
Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA
```

Or from a file:

```console
$ jolokia encrypt --file bar.txt
Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA
```

Or via `stdin` (but the command line has precedence):

```console
$ cat bar.txt | jolokia encrypt
Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA
```

By definition, you can round-trip it:

```console
$ jolokia encrypt "hello, world" -o encrypted.txt
$ jolokia decrypt -f encrypted.txt
hello, world
```

You can also encrypt or decrypt a file in-place:

```console
$ jolokia encrypt -f cat.gif --in-place
$ jolokia decrypt -f cat.gif -i
```

### Raw I/O

If you do not want base64 encoding, you can pass the `--raw` or `-r`
flag. This makes sense for larger files for which you don't want the
~33% size overhead of base64.

```console
$ jolokia encrypt --raw "hello, world" > hello.enc
$ cat hello.enc | jolokia decrypt --raw
hello, world
```

Base64 is the simplest and safest option for most users. It makes it
easy to copy-paste and share ciphertext. Use `--raw` only if you know
what you're doing.

### Compression

BYOC. jolokia does not provide built-in compression, but you can bring
your own:

```console
$ gzip -c cat.gif | jolokia encrypt -r > out.enc
$ jolokia decrypt -r -f out.enc | gunzip > cat.gif
```

If you need to compress and encrypt multiple files or directories,
consider `tar`ing them:

```console
$ tar -czf - cat.gif more-gifs/ | jolokia encrypt -r > out.enc
$ jolokia decrypt -r -f out.enc | tar -xzf -
```

It makes sense to combine compression with `--raw` to get the smallest
file size possible.

## Roadmap

- [ ] If multiple algorithms, should we keep `JOLOKIA_CIPHER_KEY` as
      default also support specialized:
      `JOLOKIA_CIPHER_KEY_CHACHA20POLY1305`?). If so, rename
      `JOLOKIA_CIPHER_KEY` to just `JOLOKIA_KEY`.
- [ ] Add tests. Test coverage is _decent_. What's missing to get to
      100% are tests for the error cases, edge cases, and false
      negatives.

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
