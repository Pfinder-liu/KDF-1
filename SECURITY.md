# Security policy

KDF-1 v1.0 deterministic behavior is frozen. General feature requests do not
change it. Serious security or deterministic-recovery problems require separate
evaluation and, for incompatible fixes, a new protocol/version.

After publication, use GitHub **Security → Report a vulnerability** if private
vulnerability reporting is enabled. It is not configured by this local package.
No dedicated contact email is currently specified. If private reporting is
unavailable, open an issue requesting a private reporting channel without
publishing exploit details or private recovery material.

Never put your real Master Phrase, Recovery Code, QR, derived password, account
recovery material or credentials in public issues, commits or reports. Use only
the clearly marked public test vectors when reproducing a problem.

Endpoint compromise and keyloggers are outside this calculator's protection.
QR is an unencrypted representation of a Recovery Code. SHA-256 checksums
detect damage; they do not authenticate a maliciously replaced distribution.
