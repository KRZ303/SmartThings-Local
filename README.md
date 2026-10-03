# scratch/test-scripts

Throwaway scripts that back up issues and pull requests on this repository.

They live on this orphan branch so that issue and PR comments can link to a
file instead of pasting a hundred lines of Python into a comment body. The
branch shares no history with `main` and is never merged into it.

## What these are, and are not

- **Not part of the library.** Nothing here ships in `smartthings-local`, and
  nothing here is imported by it. Installing the package does not give you
  these scripts, and running one does not change your installation.
- **Not maintained.** Each script was written for one question at one moment.
  The library moves; the scripts do not follow it. A script that worked when
  its comment was posted may not run against a later release, and there is no
  promise that it will be updated or removed.
- **Not a diagnostic suite.** The supported way to diagnose a connection is
  `diagnose_dtls_handshake` in the library itself, which is tested and
  documented. These are one-off probes.
- **Read before you run.** They talk to your appliance on your network. Each
  one says at the top what it sends and what it reports.

## Layout

One directory per issue or PR, named for it. Each directory holds the scripts
that were linked from that thread, plus whatever they need to run standalone.

| Directory | Thread | What it answers |
| --- | --- | --- |
| `pr-115-purepy-psk/` | [#115](https://github.com/QuiteYellow/SmartThings-Local/pull/115) | Whether a pure-Python DTLS 1.2 ECDHE-PSK client authenticates to an appliance using a binary PSK identity that contains a zero byte. |

A directory may vendor a copy of library code so the script runs without a
checkout. That copy is a snapshot taken on the date in its header. It will
drift from `main`, and `main` is the source of truth.

## Credentials

No script here contains a credential, and none should. Scripts read what they
need from environment variables and fail with a clear message when one is
missing. Keep real values in a `.env` you do not commit.

Script output is written to be safe to paste into a public thread: identifiers
are reported as a comparison result or a hash prefix rather than printed. Read
the output before you post it anyway.
