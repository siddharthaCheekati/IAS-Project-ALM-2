# ALM Project 2 — three separate websites

Each folder is an independent website with its own Python backend, frontend files, and SQLite database. All three are grouped in this one folder. No hosting account or API key is needed.

## Start on Windows

1. Install Python 3.10 or later if needed (enable “Add Python to PATH”).
2. Double-click `Start-Websites.bat`. On first use it installs the `cryptography` dependency.
3. The launcher opens a menu for all three websites. Keep its terminal open.
4. Press Ctrl+C in the launcher terminal to stop all websites.

Or run:

```text
python -m pip install -r requirements.txt
python start.py
```

| Website | Address | Main features |
|---|---|---|
| CryptoVault | http://127.0.0.1:8001 | RSA-OAEP encrypt/decrypt, RSA-PSS sign/verify, PEM keys, registration/login, public directory, self-signed X.509 downloads, stepwise DH, SHA-512 and textbook ElGamal |
| SecureTunnel | http://127.0.0.1:8002 | Stateful TLS 1.2 RSA and simplified SSH simulations, cryptographic values, AES-GCM sample transfer, interactive ESP modes |
| Sentinel | http://127.0.0.1:8003 | Persistent firewall rule creation/edit/delete, source/destination/port/protocol filtering, bastion selection, five traffic scenarios, IDS alerts, 3σ anomaly chart, threat encyclopedia |

To run only one website, enter its folder and run `python app.py`. An optional port is accepted, for example `python app.py 9001`.

## Implementation notes

- Frontends use dependency-free HTML, CSS, and JavaScript instead of the PDF's suggested React/UI-library stack. Backends use Python's standard-library HTTP server instead of Flask/FastAPI, with the cryptography package and SQLite. This keeps setup small and the project usable without a frontend build step.
- Servers bind to 127.0.0.1 only. This is an educational local project, not a publicly deployable authentication or cryptographic service.
- RSA keys are 2048-bit. Encryption uses OAEP/SHA-256; signatures use PSS/SHA-256. Maximum RSA plaintext length is 190 bytes. Registered keys are encrypted at rest with the account password; passwords use salted scrypt. Revealing a private key is an explicit learning feature.
- Certificates are self-signed, demonstrating certificate structure and a local directory, not a trusted certificate authority. Guest keys and login sessions last until server restart. Account records and firewall rules persist in each site's `data.sqlite3` file.
- Diffie-Hellman (p=23) and ElGamal (p=467) intentionally use insecure small parameters for understandable math. They are not suitable for real secrets.
- TLS follows the assignment's historical TLS 1.2 RSA key-transport sequence. It uses RSA PKCS1v15 for the pre-master secret, a TLS-style PRF, a pinned self-signed certificate, and AES-GCM sample encryption. Transcript encoding and record handling are simplified. It is not a real TLS endpoint. TLS 1.3 does not use RSA key transport. SSH is also a simplified simulation, with toy DH and generated demo host/user keys.
- Sentinel sends no real network traffic and changes no operating-system firewall settings. Rules are first-match, ordered by creation, default allow. The IDS observes traffic before filtering. Each generated batch represents a 1-second traffic sample; SSH/scan windows use actual elapsed time. Baselines use the previous 20 samples, an initial mean 8 and standard deviation 2, then a standard-deviation floor of 1. Retains 500 packets and 100 alerts per session, displaying 100 packets and eight latest alerts.
- Cookies, in-memory sessions, and private-key inspection are designed for one local learner. This project does not include production session expiry, login throttling, or external trust-chain validation.

## Suggested walkthrough

1. CryptoVault: encrypt and decrypt; sign and verify; change the plaintext and verify again to see rejection. Register, download the certificate, log out, and log back in. Walk through DH and compare shared secrets. Sign with ElGamal and modify the message before verification.
2. SecureTunnel: advance all five TLS steps, then switch to SSH. Open the IPsec explorer and compare both modes.
3. Sentinel: add a BLOCK rule for source `192.168.1.100`, generate failed SSH logins, and inspect blocked packets and the IDS alert. Generate normal HTTP traffic, then a burst to trigger anomaly detection. Edit and delete rules to compare future decisions.

## Folder contents

`CryptoVault/`, `SecureTunnel/`, `Sentinel/`: independent source files. `start.py`: shared launcher. `index.html`: menu. `requirements.txt`: Python dependency. `Start-Websites.bat`: Windows launcher.
