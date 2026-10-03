"""Build the optional Mbed TLS 3.6 shim against installed development headers.

Run explicitly at installation time, never from the integration's runtime.
Set MBEDTLS_PREFIX for a non-system installation such as Homebrew mbedtls@3.
"""
import os
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static", action="store_true", help="link Mbed TLS archives on Linux")
    arguments = parser.parse_args()
    if sys.platform not in ("linux", "darwin"):
        raise SystemExit("The optional Mbed TLS build currently supports Linux and macOS")
    directory = Path(__file__).resolve().parent
    prefix = os.environ.get("MBEDTLS_PREFIX")
    flags = []
    if prefix:
        flags = [f"-I{prefix}/include", f"-L{prefix}/lib", f"-Wl,-rpath,{prefix}/lib"]
    libraries = ["-lmbedtls", "-lmbedx509", "-lmbedcrypto"]
    if arguments.static:
        if sys.platform != "linux":
            raise SystemExit("Static Mbed TLS linking currently supports Linux only")
        libraries = ["-Wl,-Bstatic", *libraries, "-Wl,-Bdynamic", "-Wl,--exclude-libs,ALL"]
    with tempfile.TemporaryDirectory(prefix="localthings-mbedtls-", dir=directory) as temporary:
        output = Path(temporary) / "_mbedtls_native.so"
        subprocess.run([
            *shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-D_POSIX_C_SOURCE=200809L",
            "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared", *flags,
            str(directory / "_mbedtls_native.c"), *libraries,
            "-o", str(output),
        ], check=True)
        # Validate ABI/loading in another process before replacing an existing build.
        subprocess.run([sys.executable, "-c", "import ctypes,sys; lib=ctypes.CDLL(sys.argv[1]); assert lib.lt_api_version()==1", str(output)], check=True)
        output.replace(directory / output.name)
    print(directory / "_mbedtls_native.so")


if __name__ == "__main__":
    main()
