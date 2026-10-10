# Digital Signature & Certificate Verification System

A learning/demo Flask app for signing files with RSA-PSS + SHA-256 and verifying signatures against a self-signed X.509 certificate.

## Requirements
- Python 3.10+
- pip

## Run
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## How to use
1. Open **Sign document** and choose a file.
2. The app creates an RSA key pair and a self-signed X.509 certificate on first run.
3. Download the signature (`.sig`) and certificate (`.pem`).
4. Open **Verify document**, select the original file, signature, and certificate.
5. Edit the file and verify again to see a failed signature.

## Important security notes
- This is an educational prototype, not a production signing service.
- The certificate is self-signed, so it proves possession of the matching private key but is **not** trusted by an external certificate authority.
- The demo stores its private key locally in `instance/`. Do not use it for sensitive documents or expose this app publicly.
- Anyone who can replace both the document/signature and the supplied self-signed certificate can create a new matching set. For real trust, validate a certificate chain against a trusted CA and define identity/revocation policies.
