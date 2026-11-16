---
name: ssh-release-signing
description: >
  Sign release artefacts (manifest, SHA256SUMS, archives) with an SSH key, including one held in 1Password
  (op-ssh-sign, Touch ID), and verify them with ssh-keygen -Y verify against an allowed_signers file with a principal
  and a namespace. Use when a release needs a human's signature, when you must tell the human the exact signing
  commands, when a .sig is missing or has an unexpected name, or when you build allowed_signers for an installer.
  Triggers: sign the release, manifest.json.sig, SHA256SUMS.sig, ssh-keygen -Y sign, op-ssh-sign, allowed_signers,
  "No private key found"; ru: подписать релиз, подпись манифеста, ключ релиза.
---

# SSH release signing

An SSH signature (`ssh-keygen -Y sign`, the SSHSIG format) covers a file's BYTES and a NAMESPACE, not the file name.
The verifier needs an `allowed_signers` file, the PRINCIPAL to accept and the namespace.

## Hard rules

- The private key never leaves the human's agent or password manager. Agents never read, copy or export it, and never
  ask for it. The human signs, usually with Touch ID; the agent prepares the files and verifies the result.
- Give the human the public key file (`*.pub`) and the exact command. Never a private key path.
- Check the fingerprint with the human before the first signature (`release-sig fingerprint KEY.pub`), and pin the
  principal and namespace in writing.
- Verify every signature right after it is made. A signature that does not verify with the intended key is not kept.
- Never overwrite an existing `.sig`; investigate first.

## The commands to give the human

Run in the directory that holds the files and the public key `release-key.pub`:

**1Password (macOS, key in 1Password, Touch ID per signature):**

```sh
/Applications/1Password.app/Contents/MacOS/op-ssh-sign -Y sign -n NAMESPACE -f release-key.pub manifest.json
/Applications/1Password.app/Contents/MacOS/op-ssh-sign -Y sign -n NAMESPACE -f release-key.pub SHA256SUMS
ls -l *.sig
```

**Gotcha: op-ssh-sign names the signature by REPLACING the last extension.** `manifest.json` gives `manifest.sig`, not
`manifest.json.sig`. `SHA256SUMS` has no extension, so it gives `SHA256SUMS.sig`. Two files with the same stem
(`a.json`, `a.txt`) both get `a.sig`, and the second signature overwrites the first. Rename right after signing, or use the
wrapper below. The name does not affect verification.

**Through the 1Password SSH agent with plain ssh-keygen** (keeps ssh-keygen's naming, `FILE.sig`):

```sh
export SSH_AUTH_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
ssh-keygen -Y sign -f release-key.pub -n NAMESPACE manifest.json
ssh-keygen -Y sign -f release-key.pub -n NAMESPACE SHA256SUMS
```

**Any other agent** (key loaded with `ssh-add`): the same `ssh-keygen -Y sign -f KEY.pub ...` with that agent's
`SSH_AUTH_SOCK`.

`ssh-keygen ... -f KEY.pub` with no agent that holds the key fails with "No private key found" (or "agent refused").
That means the shell talks to the wrong agent. Use op-ssh-sign or set `SSH_AUTH_SOCK` as above. Never point `-f` at
the private key file to "fix" it.

## The wrapper: scripts/release-sig

```sh
RS=/path/to/skill-ssh-release-signing/scripts/release-sig
$RS fingerprint release-key.pub                       # read it aloud and compare with the human's record
$RS sign --pub release-key.pub --namespace NAMESPACE manifest.json SHA256SUMS
$RS allowed-signers --principal PRINCIPAL --namespace NAMESPACE --pub release-key.pub > allowed_signers
$RS verify --allowed-signers allowed_signers --principal PRINCIPAL --namespace NAMESPACE manifest.json SHA256SUMS
```

The human runs `sign`, which asks for Touch ID once per file. The signer is `--signer`, else op-ssh-sign if
installed, else ssh-keygen through `SSH_AUTH_SOCK`. `sign` handles each file like this:
- it signs a private copy named `payload` in a fresh temp directory, so the signer's naming rule does not matter;
- it checks the new signature against `--pub` and refuses if another key signed;
- it writes exactly `FILE.sig`, and never over an existing one.

`verify` exits 0 only when every `FILE.sig` reads `Good "NAMESPACE" signature for PRINCIPAL with ...`.

## Verify by hand

```sh
printf '%s\n' 'PRINCIPAL namespaces="NAMESPACE" ssh-ed25519 AAAA...' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I PRINCIPAL -n NAMESPACE -s manifest.json.sig < manifest.json
# Expect exactly: Good "NAMESPACE" signature for PRINCIPAL with ED25519 key SHA256:<fingerprint>
```

`allowed_signers` holds one line per accepted key: `principal namespaces="ns1,ns2" keytype base64key`. A
`namespaces=` restriction keeps a release key from validating git commits or other namespaces.

## Checklist for a release signing step

1. The agent builds the files and their digests, and writes the public key next to them with a SIGN-ME note: the
   files, the namespace, the commands above and the expected fingerprint.
2. The human checks the fingerprint, signs, and tells the agent.
3. The agent verifies each signature with the pinned principal and namespace, renames `manifest.sig` to
   `manifest.json.sig` if op-ssh-sign was used, and records the digests of the files and the signatures.
4. Installers consume `allowed_signers`, the principal (signer id) and the `.sig` files: never a key from the release
   itself.
