# Binary PSK identities

OpenSSL's DTLS 1.2 PSK callback treats an identity as a NUL-terminated string.
It cannot send a raw OCF UUID containing a zero byte intact.
The optional Mbed TLS backend sends the identity with its explicit length.

`PskAuth` selects Mbed TLS only when the identity contains a zero byte.
Certificate authentication and other PSK identities retain OpenSSL.
Both backends use the existing CoAP, cancellation, retry, and observation code.
The Mbed TLS backend permits only DTLS 1.2 with `TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256`.

## Build

Install a C compiler and Mbed TLS **3.6** development headers and libraries.
Build against the same library configuration used at runtime.
On Linux and macOS, run:

```sh
python -m smartthings_local.protocol._build_mbedtls
```

For Homebrew's versioned installation, run:

```sh
MBEDTLS_PREFIX="$(brew --prefix mbedtls@3)" python -m smartthings_local.protocol._build_mbedtls
```

The command creates `_mbedtls_native.so` beside the Python backend.
The ordinary wheel contains source, not a platform-specific binary.
No compiler runs during authentication or integration setup.
A missing or incompatible binary causes validation to fail before any network request.
An identity containing zero bytes never falls back to OpenSSL.

Linux builders can use `--static` with position-independent Mbed TLS archives.
This isolates the backend from another Mbed TLS version loaded by the host process.
Build separately for each architecture and C library.
Do not copy a macOS binary into a Linux installation.
Package or integration updates can remove local patches; retain deployment backups.

## Evidence and limits

I authenticated my Samsung LCD oven, profile `DA-KS-OVEN-0105X`, through Mbed TLS 3.6.7 on 2026-10-03.
My owner UUID contained a zero byte.
A read-only GET of `/oic/d` returned the expected device identity.
Both a standalone native probe and the Python session performed that read.
This observation does not establish compatibility with other appliance models.

The tests exchange encrypted records with a local OpenSSL peer using synthetic binary identities.
They check identity length, zero-byte positions, missing-backend rejection, retransmission timing, and native cleanup.
Run these tests after building the native backend:

```sh
python -m pytest tests/test_mbedtls.py tests/test_psk_auth.py
```

The existing credential-acquisition and device-identity requirements still apply.
This backend neither acquires a PSK nor writes OCF security resources.
