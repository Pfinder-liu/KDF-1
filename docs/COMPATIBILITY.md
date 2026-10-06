# Compatibility evidence — v1.0

User-reported existing tests: Intel Mac PASS; Apple Silicon Mac PASS;
Windows / Parallels Desktop PASS. The user confirmed identical passwords for
identical inputs on Intel and Apple Silicon. Browser/build details were not
provided for every user-reported environment; these are not independent
re-runs by this packaging task.

Recorded A1/A2 verification on Apple Silicon: Chrome 154 and Safari 27 local
file startup self-test and classic vector PASS; raw newline paste rejection,
ordinary paste and Show/Hide verified. Node 24 Unicode 17 and Python Unicode 13
passed the same fixed Unicode 13 repertoire and normalization corpus.

Final ZIP local browser verification is recorded in FINAL_VALIDATION.txt.
Linux and other browser/OS combinations have no recorded manual validation.
No claim of universal compatibility is made. Test on the intended computer.

Root COMPATIBILITY.txt, VALIDATION.txt and FREEZE_REAUDIT.txt are preserved
historical candidate evidence. Their earlier NOT TESTED/candidate statements
describe that earlier point in time; this document records later evidence.
Physical QR scanning and the no-copy/paste second-computer paper rehearsal are
remaining human validation evidence, not claimed performed in this package.
