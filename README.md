# KDF-1 v1.0 — FROZEN

KDF-1 deterministically derives passwords for a few personal recovery-root
accounts, such as primary email, from a remembered **Master Phrase**, a saved
128-bit **Recovery Code**, and explicit label/account/revision/length records.
It helps you recover when devices or your password manager are unavailable.

It is not a password manager and does not replace account-provider recovery,
2FA, passkeys or provider recovery codes. It cannot restore a missing Recovery
Code or phrase, infer lost labels, or protect secrets on a compromised computer
or against a keylogger. Use a reasonably trusted, private computer.

## Recover offline

Download the named `KDF-1-v1.0-FROZEN.zip` asset from the v1.0 Release, unzip,
read [START_HERE.txt](START_HERE.txt), and open [RECOVER.html](RECOVER.html).
The calculator automatically verifies embedded files and public vectors.
**Wait for SELF TEST PASS before entering secrets. STOP means do not proceed.**
No Python, Node, package manager, server or internet is needed. Keep your own
offline copy before a disaster. The “公开验证” button runs more public vectors;
it clears inputs. Developer tests are optional materials, not recovery setup.

For first use, choose **Create NEW Recovery Code**. Web Crypto
`crypto.getRandomValues` supplies 16 random bytes; HRC-1 encodes them as grouped
uppercase text with a typo checksum. Save/print it separately from your phrase.
A new code cannot recover passwords created with another code. Recovery input
stays visible; Master Phrase starts hidden and supports Show/Hide. CR/LF and
characters outside the frozen repertoire are rejected, never silently corrected.

**Anonymous Travel QR** contains only the same Human Recovery Code. It is not
encrypted: anyone photographing/scanning it obtains that code. A strong phrase
is still required and can be guessed offline by someone holding the code.
QR-only PNG/printing contains no account metadata. Disable browser print
headers/footers. Scan using the system camera; this calculator has no scanner.
Keep label/account/revision/length records separately and rehearse with public
data using [HUMAN-DRILL.txt](HUMAN-DRILL.txt).

## Frozen authority

**The specification and public reference vectors define KDF-1 v1.0.**
[SPEC.txt](SPEC.txt) defines KDF-1, HRC-1 and the input contract;
[vectors/INDEX.txt](vectors/INDEX.txt) lists public conformance files.
**RECOVER.html is the KDF-1 v1.0 Reference Recovery Calculator.** Future
implementations can reproduce the protocol without this browser or Python.

[FREEZE.txt](FREEZE.txt) freezes deterministic behavior. To preserve audited
bytes, internal candidate labels remain historical; FREEZE.txt supersedes their
administrative status only. No algorithm, input rule or reference output changed.
Incompatible changes require a new protocol. Never overwrite v1.0 assets/tag.

## Validation and publication

[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) separates user-reported Intel Mac,
Apple Silicon and Windows/Parallels PASS from the current local browser checks.
This is evidence for tested environments, not every browser/OS guarantee.
[docs/FINAL_VALIDATION.txt](docs/FINAL_VALIDATION.txt) records final ZIP checks.
[FREEZE_REAUDIT.txt](FREEZE_REAUDIT.txt) is the historical pre-freeze audit.

The internal SHA256SUMS.txt covers bundle files, excluding itself and
INTEGRITY.json to avoid a checksum cycle. INTEGRITY.json covers all other
bundle files, including that manifest. The external release/SHA256SUMS.txt
also covers the final ZIP. These check damage/accidental changes, not identity
or authenticity against an attacker replacing the package and manifest.

Never submit real Master Phrases, Recovery Codes, private QR images or production
passwords to GitHub. `.gitignore` is a convenience, not secret detection.
[SECURITY.md](SECURITY.md) describes reporting. KDF-1-owned material is MIT;
third-party material retains its licenses in [licenses/](licenses/).
Python `reference/` and Node `developer/` are development/reference materials.
`developer/legacy/` is historical tooling, not the emergency recovery path.

For a first GitHub publication on Mac, follow
[GITHUB_PUBLISHING_FOR_BEGINNERS.txt](GITHUB_PUBLISHING_FOR_BEGINNERS.txt).
No account, remote repository, upload or push has been performed for you.
