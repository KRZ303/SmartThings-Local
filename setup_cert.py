#!/usr/bin/env python3
"""
setup_cert.py — One-shot client cert generator for local DTLS-CoAP
access to Samsung appliances on your LAN.

Builds a client cert keyed to the identity that each appliance's factory
ACL already grants `perm=31` on `href=*`.

Steps:

1. Take the UUID the appliance authorizes on. It is the constant
   `CLIENT_UUID` below, since it does not rotate; `UUID=<uuid>` overrides
   it. This is the only field the appliance checks.
2. Generate a fresh RSA-2048 key pair of your own.
3. Build a CSR with the UUID in CN, OU, and SAN.
4. Sign the leaf. By default it signs itself, with no CA anywhere: on the
   appliances tested the device did not validate the signer or chain. With
   `--fallback`, sign with the public AC14K_M intermediate instead (the
   pre-2026 path), for a device that does validate the chain.
5. Assemble `client.key`, `client.pem`, `client_fullchain.pem`.

Nothing here touches an appliance. The UUID is a constant, the key and
the leaf are minted locally by `openssl`, and the only network access is
the `--fallback` bundle fetch. To find out what a device makes of the
result, see "Checking the cert against a device" below.

Background:

- The UUID is a cloud service identity, published in the subject DN of a
  public server certificate. It is pinned by the installed base: rotating
  it would mean pushing an ACL change to every appliance in the field.
- TizenRT iotivity locates the peer UUID via `memmem(subject, "uuid:")`,
  so the same UUID in any RDN works.
- The default self-signed path needs no CA at all. `--fallback` uses the
  AC14K_M intermediate, which has been public for years; it is only needed
  for a device that validates the chain.

Fallback if the --fallback bundle fetch fails:

  # Manual AC14K_M bundle (point at any mirror)
  AC14K_M_CERT_BUNDLE=/path/to/cert.pem python setup_cert.py --fallback

Usage:

    python setup_cert.py                 # self-signed (default)
    python setup_cert.py --fallback      # AC14K_M-signed (pre-2026 path)

Env overrides (all optional; AC14K_M_* apply only with --fallback):
    AC14K_M_CERT         AC14K_M cert PEM (skip live fetch)
    AC14K_M_KEY          AC14K_M private key PEM
    AC14K_M_CERT_BUNDLE  combined PEM (key + 4 certs)
    CHAIN_DIR            dir containing cert_1..4.pem
    BRAYSTORM_URL        bundle source URL
    UUID                 override CLIENT_UUID
    OUT_DIR              output dir (default ./certs/)

Checking the cert against a device:

    python -m smartthings_local.protocol.dtls_probe <ip> <port> --diagnostic \
        --cert certs/client_fullchain.pem --key certs/client.key

`--diagnostic` reports the server's own flight and any fatal alert, so a
refusal names itself: `alert=unknown_ca` is the OCF-PKI wall (issue #16),
a bare `handshake_failure` is something else. Find <port> with
`discover_ocf_secure_ports`; it is assigned by the appliance and differs
between units, so there is no default worth guessing at.

A completed handshake is not proof the certificate authorized: these
appliances complete one with no client certificate at all. What settles
that is an authenticated read, `GET /oic/sec/acl` returning 2.05 rather
than 4.01, over a `DtlsCoapSession`.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


CLIENT_UUID = 'ab0b0ac4-aae9-4958-a04d-8ec36fe1b2f9'

BRAYSTORM_URL = (
    'https://raw.githubusercontent.com/brayStorm/samsung-appliance-token/main/cert.pem'
)

BUNDLE_CERT_NAMES = ['ac14k_m.pem', 'cert_2.pem', 'cert_3.pem', 'cert_4.pem']


def split_bundle_pem(text):
    """Split a combined PEM into (key_pem, [cert_pem, ...]).
    Expects 1 private key + 4 certificates (leaf + 3 upstream)."""
    key_re = re.compile(
        r'-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----',
        re.DOTALL)
    cert_re = re.compile(
        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        re.DOTALL)
    keys = key_re.findall(text)
    certs = cert_re.findall(text)
    if len(keys) != 1:
        raise ValueError(f"expected 1 private key block, found {len(keys)}")
    if len(certs) != 4:
        raise ValueError(f"expected 4 certificate blocks, found {len(certs)}")
    return keys[0] + '\n', [c + '\n' for c in certs]


def fetch_ac14k_bundle(dest_dir, timeout=15):
    """Download and split the AC14K_M bundle. Returns
    {ac14k_cert, ac14k_key, chain_dir} of paths in dest_dir."""
    url = os.environ.get('BRAYSTORM_URL', BRAYSTORM_URL)
    print(f"  Fetching AC14K_M bundle...")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        raise RuntimeError(f"bundle fetch failed: {e}") from e

    key_pem, cert_pems = split_bundle_pem(data)

    dest = Path(dest_dir); dest.mkdir(parents=True, exist_ok=True)
    key_path = dest / 'ac14k_m.key'
    key_path.write_text(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    cert_paths = []
    for name, pem in zip(BUNDLE_CERT_NAMES, cert_pems):
        p = dest / name
        p.write_text(pem)
        cert_paths.append(p)
    (dest / 'cert_1.pem').write_text(cert_pems[0])

    return {
        'ac14k_cert': cert_paths[0],
        'ac14k_key':  key_path,
        'chain_dir':  dest,
    }


def verify_cert_key_pair(cert_path, key_path):
    """Compare modulus to confirm cert and key pair."""
    def modulus(args):
        out = subprocess.run(
            ['openssl'] + args, capture_output=True, text=True, check=True).stdout
        m = re.search(r'Modulus=([0-9A-Fa-f]+)', out)
        return m.group(1) if m else None
    try:
        cm = modulus(['x509', '-noout', '-modulus', '-in', str(cert_path)])
        km = modulus(['rsa', '-noout', '-modulus', '-in', str(key_path)])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openssl modulus extraction failed: {e.stderr}") from e
    if not cm or not km:
        raise RuntimeError("could not extract modulus from cert and/or key")
    if cm != km:
        raise RuntimeError(
            f"AC14K_M cert and key do not pair (cert modulus != key modulus)")


# OpenSSL config that force-enables SHA-1 signatures, for the --fallback
# path only. That path signs the leaf with SHA-1 to match the pre-2026
# AC14K_M recipe; Fedora/RHEL (and some hardened OpenSSL 3.x builds) reject
# SHA-1 signing under the default crypto policy, so re-enable it just for
# that signing step via a scoped OPENSSL_CONF. The default self-signed path
# uses SHA-256 and needs none of this.
SHA1_OVERRIDE_CONF = """\
openssl_conf = openssl_init

[openssl_init]
alg_section = evp_properties

[evp_properties]
rh-allow-sha1-signatures = yes
"""


class CommandError(RuntimeError):
    """A subprocess exited non-zero; carries the command and its output."""


def run(cmd, **kw):
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or '').strip()
        raise CommandError(
            f"command failed (exit {proc.returncode}): {' '.join(cmd)}"
            + (f"\n{detail}" if detail else ""))
    return proc


def run_allow_sha1(cmd):
    """Run an openssl command with SHA-1 signatures force-enabled, for
    distros whose crypto policy otherwise blocks SHA-1 signing."""
    version = run(['openssl', 'version']).stdout.strip()
    if not version.startswith('OpenSSL 3.'):
        # The provider configuration below is specific to OpenSSL 3.
        # LibreSSL can exit successfully without running the requested
        # command when it is given that configuration, leaving no output
        # certificate behind. Older OpenSSL releases do not need the
        # provider override either, so retry them with a clean environment.
        env = dict(os.environ)
        env.pop('OPENSSL_CONF', None)
        return run(cmd, env=env)

    conf = tempfile.NamedTemporaryFile(
        'w', suffix='.cnf', prefix='sha1_ok_', delete=False)
    conf.write(SHA1_OVERRIDE_CONF)
    conf.close()
    try:
        return run(cmd, env=dict(os.environ, OPENSSL_CONF=conf.name))
    finally:
        os.unlink(conf.name)


def mint_cert(uuid, ac14k_cert, ac14k_key, chain_files, out_dir):
    """Mint a fresh-keyed client cert with UUID in CN+OU+SAN, signed by
    AC14K_M with SHA-1. Returns dict of output paths."""
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    paths = {
        'key':       out / 'client.key',
        'csr':       out / 'client.csr',
        'leaf':      out / 'client.pem',
        'fullchain': out / 'client_fullchain.pem',
        'ext':       out / 'ext.cnf',
        'srl':       out / 'client.srl',
    }

    paths['ext'].write_text(f"""basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth, 1.3.6.1.4.1.51414.0.1.2
subjectAltName = @alt_names
1.3.6.1.4.1.51414.1.3 = ASN1:UTF8String:samsung.role.hub

[alt_names]
URI.1 = urn:uuid:{uuid}
URI.2 = uri:uuid:{uuid}
URI.3 = uuid:{uuid}
DNS.1 = {uuid}
""")

    run(['openssl', 'genrsa', '-out', str(paths['key']), '2048'])
    try:
        os.chmod(paths['key'], 0o600)
    except OSError:
        pass

    subject = (
        f"/OU=uuid:{uuid}"
        f"/CN=urn:uuid:{uuid}"
        f"/O=Samsung Electronics"
        f"/C=KR"
    )
    run(['openssl', 'req', '-new', '-key', str(paths['key']),
         '-out', str(paths['csr']), '-subj', subject])

    sign_cmd = ['openssl', 'x509', '-req', '-in', str(paths['csr']),
                '-CA', str(ac14k_cert), '-CAkey', str(ac14k_key),
                '-CAcreateserial', '-CAserial', str(paths['srl']),
                '-out', str(paths['leaf']), '-days', '3650',
                '-extfile', str(paths['ext']), '-sha1']
    try:
        run(sign_cmd)
    except CommandError as first:
        # Most likely the local crypto policy blocks SHA-1 signing
        # (common on Fedora/RHEL). Retry once with SHA-1 force-enabled;
        # if that still fails, surface the original error.
        print("  SHA-1 signing was rejected by the local OpenSSL policy; "
              "retrying with a SHA-1 override...")
        try:
            run_allow_sha1(sign_cmd)
        except CommandError:
            raise first

    parts = [paths['leaf'].read_text()]
    for p in chain_files:
        parts.append(Path(p).read_text())
    paths['fullchain'].write_text(''.join(parts))

    return paths


def mint_self_signed(uuid, out_dir):
    """Mint a self-signed client cert carrying the UUID. Default path.

    The leaf signs itself: there is no CA anywhere, and the fullchain PEM
    holds that one certificate.

    On the appliances tested, the device did not validate the client
    certificate's signer or chain; authorization was by the subject UUID,
    matched against the on-device ACL. There, a self-signed leaf read and
    wrote exactly what an AC14K_M-signed one did, with signer, chain,
    digest, key, org, and vendor OIDs all cosmetic and only the UUID
    mattering. Four appliances across four model families, two of them
    reported on issue #96. A device that does validate the chain (see
    docs/ocf-pki-laundry.md) needs the --fallback path, and rejects
    AC14K_M anyway; that is what --fallback and the loud-failure-then-
    report flow are for.

    Output names match mint_cert -- client.key + client_fullchain.pem --
    so both paths drop into the same README, bridge config and deploy
    steps.
    """
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    paths = {
        'key':       out / 'client.key',
        'csr':       out / 'client.csr',
        'leaf':      out / 'client.pem',
        'fullchain': out / 'client_fullchain.pem',
        'ext':       out / 'ext.cnf',
    }

    # Subject/SAN carry only the UUID. Standard EKU, no vendor OIDs, no
    # org/country -- all verified cosmetic on hardware.
    paths['ext'].write_text(f"""basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @alt_names

[alt_names]
URI.1 = urn:uuid:{uuid}
URI.2 = uri:uuid:{uuid}
URI.3 = uuid:{uuid}
DNS.1 = {uuid}
""")

    run(['openssl', 'genrsa', '-out', str(paths['key']), '2048'])
    try:
        os.chmod(paths['key'], 0o600)
    except OSError:
        pass

    run(['openssl', 'req', '-new', '-key', str(paths['key']),
         '-out', str(paths['csr']),
         '-subj', f'/OU=uuid:{uuid}/CN=urn:uuid:{uuid}'])
    run(['openssl', 'x509', '-req', '-in', str(paths['csr']),
         '-signkey', str(paths['key']),
         '-out', str(paths['leaf']), '-days', '3650',
         '-extfile', str(paths['ext']), '-sha256'])

    paths['fullchain'].write_text(paths['leaf'].read_text())
    return paths


def resolve_ac14k_inputs(out_dir):
    """Return (ac14k_cert, ac14k_key, chain_files).

    Resolution order: env-supplied cert+key+chain dir, then env-supplied
    combined bundle, then live fetch from BRAYSTORM_URL."""
    env_cert = os.environ.get('AC14K_M_CERT')
    env_key  = os.environ.get('AC14K_M_KEY')
    env_dir  = os.environ.get('CHAIN_DIR')
    env_bundle = os.environ.get('AC14K_M_CERT_BUNDLE')

    if env_cert and env_key and env_dir:
        print(f"  Using AC14K_M materials from env vars")
        for path, label in [(env_cert, 'AC14K_M_CERT'), (env_key, 'AC14K_M_KEY')]:
            if not Path(path).is_file():
                raise FileNotFoundError(f"{label} not found: {path}")
        chain = sorted(Path(env_dir).glob('cert_*.pem'))
        if len(chain) < 4:
            raise RuntimeError(
                f"CHAIN_DIR needs cert_1..cert_4.pem (leaf + 3 upstream); "
                f"found: {[p.name for p in chain]}")
        return Path(env_cert), Path(env_key), chain

    bundle_dir = Path(out_dir) / '.bundle'

    if env_bundle:
        print(f"  Splitting AC14K_M bundle from {env_bundle}")
        text = Path(env_bundle).read_text()
        key_pem, cert_pems = split_bundle_pem(text)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        key_path = bundle_dir / 'ac14k_m.key'
        key_path.write_text(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        for name, pem in zip(BUNDLE_CERT_NAMES, cert_pems):
            (bundle_dir / name).write_text(pem)
        (bundle_dir / 'cert_1.pem').write_text(cert_pems[0])
        chain = sorted(bundle_dir.glob('cert_*.pem'))
        return bundle_dir / 'ac14k_m.pem', key_path, chain

    try:
        result = fetch_ac14k_bundle(bundle_dir)
    except Exception as e:
        msg = (
            f"\n[!] Could not fetch AC14K_M bundle: {e}\n"
            f"\n  Workarounds:\n"
            f"    - Point at a local PEM:  AC14K_M_CERT_BUNDLE=/path/to/cert.pem python setup_cert.py\n"
            f"    - Point at a mirror:     BRAYSTORM_URL=https://<mirror>/cert.pem python setup_cert.py\n"
        )
        print(msg, file=sys.stderr)
        raise SystemExit(3)
    chain = sorted(result['chain_dir'].glob('cert_*.pem'))
    return result['ac14k_cert'], result['ac14k_key'], chain


def main():
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    p.add_argument('--fallback', action='store_true',
                   help='Mint an AC14K_M-signed cert (the pre-2026 path) instead of '
                        'the default self-signed cert. Use only if a device rejects '
                        'the self-signed cert -- and please report the model.')
    args = p.parse_args()

    out_dir    = os.environ.get('OUT_DIR', './certs/')
    uuid_override = os.environ.get('UUID')

    # Phase 1: identify the UUID. Both paths need it, and it is the only
    # field the appliance authorizes on.
    print("=" * 60)
    print("Phase 1: identify peer UUID")
    print("=" * 60)
    if uuid_override:
        uuid = uuid_override.lower()
        print(f"  Using UUID from env: {uuid}")
    else:
        uuid = CLIENT_UUID
        print(f"  Using UUID: {uuid}")

    # Phase 2: mint. Self-signed by default; AC14K_M-signed under --fallback.
    print()
    print("=" * 60)
    if args.fallback:
        print(f"Phase 2: mint AC14K_M-signed cert (--fallback) with UUID {uuid}")
    else:
        print(f"Phase 2: mint self-signed cert with UUID {uuid}")
    print("=" * 60)

    if args.fallback:
        try:
            ac14k_cert, ac14k_key, chain_files = resolve_ac14k_inputs(out_dir)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
        print(f"  AC14K_M cert: {ac14k_cert}")
        print(f"  AC14K_M key:  {ac14k_key}")
        print(f"  chain:        {len(chain_files)} certs "
              f"({', '.join(pp.name for pp in chain_files)})")
        try:
            verify_cert_key_pair(ac14k_cert, ac14k_key)
        except RuntimeError as e:
            print(f"[!] AC14K_M cert/key sanity check failed: {e}", file=sys.stderr)
            return 2
        print(f"  cert/key modulus pair OK")
        try:
            paths = mint_cert(uuid, ac14k_cert, ac14k_key, chain_files, out_dir)
        except CommandError as e:
            print(f"\n[!] Failed to mint the client cert:\n{e}", file=sys.stderr)
            print(
                "\n  If the failure mentions SHA-1 / disabled digests, your "
                "OpenSSL build blocks SHA-1 signing (common on Fedora/RHEL).\n"
                "  The --fallback path signs the leaf with SHA-1; allow it and re-run:\n"
                "    sudo update-crypto-policies --set DEFAULT:SHA1\n"
                "  (or LEGACY). Undo afterwards with: "
                "sudo update-crypto-policies --set DEFAULT\n"
                "  Or drop --fallback: the self-signed cert needs no SHA-1.",
                file=sys.stderr)
            return 4
    else:
        try:
            paths = mint_self_signed(uuid, out_dir)
        except CommandError as e:
            print(f"\n[!] Failed to mint the self-signed cert:\n{e}", file=sys.stderr)
            return 4

    print(f"  key:       {paths['key']}")
    print(f"  leaf:      {paths['leaf']}")
    print(f"  fullchain: {paths['fullchain']}")

    subj_out = run(['openssl', 'x509', '-in', str(paths['leaf']), '-noout', '-subject'])
    print(f"  Subject: {subj_out.stdout.strip().replace('subject=', '')}")

    print()
    print("=" * 60)
    print("Done. Output dir:", Path(out_dir).resolve())
    print("=" * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
