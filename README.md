# skill-ssh-release-signing

Sign release artefacts with an SSH key (also one held in 1Password) and verify them with `ssh-keygen -Y verify`,
an `allowed_signers` file, a principal and a namespace.

- Instructions for agents and the exact human commands: [SKILL.md](SKILL.md)
- The wrapper: `scripts/release-sig` (Python 3 stdlib + OpenSSH)
- Tests: `sh tests/run.sh` (throwaway keys in a scratch dir; CI on Ubuntu and macOS)

## Tools

| Tool | Use | Run | Output |
| --- | --- | --- | --- |
| `scripts/release-sig` | sign, verify, allowed-signers line, fingerprint | `python3 -I scripts/release-sig --help` | `FILE.sig` next to each file |
| `tests/run.sh` | unit tests with generated keys | `sh tests/run.sh` | none (scratch removed) |

License: Apache-2.0.
