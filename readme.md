
# Diffie Hellman Security

C++ suite demonstrating Diffie-Hellman key exchange: basic, MITM attack, and RSA-secured versions.

## Features
- `dh_basic`: Basic DH key exchange.
- `dh_mitm`: Man-in-the-middle attack demo.
- `dh_secure`: DH secured with RSA signatures.

## Requirements
- OpenSSL library
- C++ compiler (e.g., g++)

## Build
```bash
make all
```
Executables appear in `bin/`.

## Usage
- **Basic DH**:  
  ```bash
  ./bin/dh_basic  # Unix
  bin/dh_basic.exe  # Windows
  ```
  - Enter prime (p), generator (g).

- **MITM Attack**:  
  ```bash
  ./bin/dh_mitm  # Unix
  bin/dh_mitm.exe  # Windows
  ```
  - Enter prime (p), generator (g).

- **Secure DH**:  
  ```bash
  ./bin/dh_secure  # Unix
  bin/dh_secure.exe  # Windows
  ```
  - Enter d1 (27), d2 (29), prime (p), generator (g).

- **Clean**:  
  ```bash
  make clean
  ```

## Files
- `data/publickey.txt`: RSA keys for `dh_secure` (e.g., 3, 55, 5, 91).

## Example Usage
- `dh_basic`: `p=23, g=5` → Shared key = 2  
- `dh_mitm`: `p=23, g=5` → Alice-Mallory = 12, Bob-Mallory = 9  
- `dh_secure`: `d1=27, d2=29, p=23, g=5` → Shared key = 2

## Notes
- Cross-platform (Linux/Windows) via Makefile.
- Store `publickey.txt` in `data/`.
- Originally an academic exercise, enhanced for demonstration.



