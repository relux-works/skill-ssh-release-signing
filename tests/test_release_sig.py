"""Tests for scripts/release-sig with throwaway keys made in a scratch dir. Needs OpenSSH ssh-keygen and ssh-agent."""
import importlib.machinery, importlib.util, os, shutil, subprocess, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "scripts", "release-sig")
_loader = importlib.machinery.SourceFileLoader("release_sig", TOOL)
_spec = importlib.util.spec_from_loader("release_sig", _loader)
rs = importlib.util.module_from_spec(_spec)
_loader.exec_module(rs)

NS = "example-release"

# A signer that behaves like op-ssh-sign for naming: it writes <file minus its last extension>.sig.
FAKE_OP = """#!/bin/sh
set -eu
ns=""; file=""
while [ $# -gt 0 ]; do
  case "$1" in -Y) shift 2;; -n) ns=$2; shift 2;; -f) shift 2;; *) file=$1; shift;; esac
done
ssh-keygen -q -Y sign -n "$ns" -f "$FAKE_SIGN_KEY" "$file"
dir=$(dirname "$file"); base=$(basename "$file"); stem="${base%.*}"
[ "$stem" = "$base" ] || mv "$file.sig" "$dir/$stem.sig"
"""


def keygen(d, name):
    k = os.path.join(d, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", k], check=True)
    return k


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.key = keygen(self.d, "release")
        self.other = keygen(self.d, "other")
        self.fake = os.path.join(self.d, "fake-op-ssh-sign")
        with open(self.fake, "w") as f:
            f.write(FAKE_OP)
        os.chmod(self.fake, 0o755)
        self.files = []
        for name, body in (("manifest.json", b'{"commit":"abc"}\n'), ("SHA256SUMS", b"00  x\n"), ("a.tar.gz", b"\x1f\x8b")):
            p = os.path.join(self.d, name)
            with open(p, "wb") as f:
                f.write(body)
            self.files.append(p)
        self.allowed = os.path.join(self.d, "allowed_signers")
        with open(self.allowed, "w") as f:
            f.write(rs.allowed_line("release-principal", NS, self.key + ".pub") + "\n")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def sign(self, signer_key, files=None, pub=None, signer=None):
        os.environ["FAKE_SIGN_KEY"] = signer_key
        try:
            return rs.main(["release-sig", "sign", "--pub", pub or self.key + ".pub", "--namespace", NS,
                            "--signer", signer or self.fake] + (files or self.files))
        finally:
            os.environ.pop("FAKE_SIGN_KEY")

    def verify(self, principal="release-principal", ns=NS, files=None):
        return rs.main(["release-sig", "verify", "--allowed-signers", self.allowed, "--principal", principal,
                        "--namespace", ns] + (files or self.files))


class Sign(Base):
    # Claim: with an op-ssh-sign-like signer (which names manifest.json's signature manifest.sig), every file gets
    # exactly FILE.sig, and all of them verify for the principal and namespace.
    def test_names_normalized_and_verify(self):
        self.assertEqual(self.sign(self.key), 0)
        for f in self.files:
            self.assertTrue(os.path.isfile(f + ".sig"), f)
        self.assertFalse(os.path.exists(os.path.join(self.d, "manifest.sig")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "a.tar.sig")))
        self.assertEqual(self.verify(), 0)

    # Claim: a signer that signs with a DIFFERENT key than --pub is refused before any FILE.sig is written.
    def test_wrong_key_refused(self):
        import contextlib, io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.sign(self.other), 2)
        self.assertIn("does not verify with", err.getvalue())  # refused by the self-check, not by a signer failure
        self.assertFalse(any(os.path.exists(f + ".sig") for f in self.files))

    # Claim: an existing FILE.sig is never overwritten; the run refuses before signing anything, and the old bytes stay.
    def test_no_overwrite(self):
        with open(self.files[0] + ".sig", "w") as f:
            f.write("old")
        self.assertEqual(self.sign(self.key), 2)
        with open(self.files[0] + ".sig") as f:
            self.assertEqual(f.read(), "old")
        self.assertFalse(os.path.exists(self.files[1] + ".sig"))

    # Claim: the plain ssh-keygen path works through an ssh-agent that holds the key (the private key file is not
    # passed to the tool), as on a host without 1Password.
    def test_agent_path(self):
        sock = os.path.join(self.d, "agent.sock")
        agent = subprocess.Popen(["ssh-agent", "-D", "-a", sock], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if os.path.exists(sock):
                    break
                subprocess.run(["sleep", "0.1"])
            env = dict(os.environ, SSH_AUTH_SOCK=sock)
            subprocess.run(["ssh-add", "-q", self.key], env=env, check=True, capture_output=True)
            p = subprocess.run(["python3", "-I", TOOL, "sign", "--pub", self.key + ".pub", "--namespace", NS,
                                "--signer", shutil.which("ssh-keygen"), self.files[0]], env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(self.verify(files=self.files[:1]), 0)
        finally:
            agent.terminate()
            agent.wait()


class Verify(Base):
    # Claim: verification fails for a wrong namespace, a wrong principal, a changed file, swapped signatures, and an
    # allowed_signers entry for another key; the untouched set beside each case verifies (control).
    def test_refusals_with_control(self):
        self.assertEqual(self.sign(self.key), 0)
        self.assertEqual(self.verify(), 0)
        self.assertEqual(self.verify(ns="other-namespace"), 1)
        self.assertEqual(self.verify(principal="someone-else"), 1)
        m = self.files[0]
        shutil.copyfile(self.files[1] + ".sig", os.path.join(self.d, "swap"))
        shutil.copyfile(m + ".sig", self.files[1] + ".sig")
        self.assertEqual(self.verify(files=self.files[1:2]), 1)
        shutil.copyfile(os.path.join(self.d, "swap"), self.files[1] + ".sig")
        self.assertEqual(self.verify(), 0)
        with open(m, "ab") as f:
            f.write(b" ")
        self.assertEqual(self.verify(files=[m]), 1)
        self.assertEqual(self.verify(files=self.files[1:]), 0)
        with open(self.allowed, "w") as f:
            f.write(rs.allowed_line("release-principal", NS, self.other + ".pub") + "\n")
        self.assertEqual(self.verify(files=self.files[1:]), 1)

    # Claim: a missing signature refuses the whole check (exit 2); it is never skipped.
    def test_missing_sig(self):
        self.assertEqual(self.verify(files=self.files[:1]), 2)


class Lines(Base):
    # Claim: the allowed_signers line has the exact form principal namespaces="NS" type key, and malformed principals,
    # namespaces or non-key files are refused.
    def test_allowed_line(self):
        with open(self.key + ".pub") as f:
            kt, key = f.read().split()[:2]
        self.assertEqual(rs.allowed_line("p1", NS, self.key + ".pub"), 'p1 namespaces="%s" %s %s' % (NS, kt, key))
        for args in (("p 1", NS, self.key + ".pub"), ("p1", 'x" y', self.key + ".pub"), ("p1", NS, self.files[0])):
            with self.subTest(args=args), self.assertRaises(rs.Refused):
                rs.allowed_line(*args)
        self.assertTrue(rs.fingerprint(self.key + ".pub").startswith("SHA256:"))


if __name__ == "__main__":
    unittest.main()
