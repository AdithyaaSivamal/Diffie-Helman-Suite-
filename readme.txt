Diffie-Hellman Key Exchange Suite
=================================
Purpose: Demonstrates Diffie-Hellman key exchange with three programs:
- `dh_basic`: Basic DH key exchange.
- `dh_mitm`: Shows a man-in-the-middle attack.
- `dh_secure`: Secures DH with RSA signatures.

Compilation:
- Requires OpenSSL library and C++ compiler (e.g., g++).
- Run `make all` to build all programs.

Usage:
- Run `./bin/dh_basic` or `bin/dh_basic.exe`: Enter prime (p) and generator (g).
- Run `./bin/dh_mitm` or `bin/dh_mitm.exe`: Enter prime (p) and generator (g).
- Run `./bin/dh_secure` or `bin/dh_secure.exe`: Enter Alice’s private key (d1), Bob’s private key (d2), prime (p), and generator (g).
- Clean: `make clean`.

Files Needed:
- data/publickey.txt: RSA keys for `dh_secure` (e1, n1, e2, n2, one per line).
  Example:
  3
  323
  65537
  589

Example Usage:
====================

- `bin/dh_basic.exe`:
	Enter prime number (p): 23
	Enter generator (g): 5
	Alice's public key (A) = 8
	Bob's public key (B) = 19
	Shared key = 2

- `bin/dh_mitm.exe`:
	Enter prime number (p): 23
	Enter generator (g): 5
	Alice-Mallory key = 12
	Bob-Mallory key = 9

- `bin/dh_secure.exe`:
	Enter Alice's private key (d1): 27
	Enter Bob's private key (d2): 29
	Enter prime number (p): 23
	Enter generator (g): 5
	Shared key = 2

Notes:
- Works on Linux/Windows with Makefile.
- Store `publickey.txt` in `data/` directory.
