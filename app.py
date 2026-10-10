from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta, timezone
import io
import os

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
UPLOADS = ROOT / "uploads"
INSTANCE.mkdir(exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-secret")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB demo limit
PRIVATE_KEY_PATH = INSTANCE / "private_key.pem"
CERT_PATH = INSTANCE / "certificate.pem"


def ensure_identity():
    if PRIVATE_KEY_PATH.exists() and CERT_PATH.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Digital Signature Demo User"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Student Cryptography Project"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    PRIVATE_KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_private_key():
    ensure_identity()
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def safe_name(name):
    return secure_filename(name) or "document.bin"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        file = request.files.get("document")
        if not file or not file.filename:
            flash("Choose a document to sign.", "error")
            return redirect(url_for("sign"))
        filename = safe_name(file.filename)
        data = file.read()
        key = load_private_key()
        signature = key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        sig_name = filename + ".sig"
        sig_path = UPLOADS / sig_name
        sig_path.write_bytes(signature)
        flash(f"Signature created for {filename}. Download the signature and certificate.", "success")
        return render_template("sign.html", signed=True, filename=filename,
                               sig_name=sig_name, cert_name="certificate.pem")
    return render_template("sign.html", signed=False)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    if request.method == "POST":
        doc = request.files.get("document")
        sig = request.files.get("signature")
        cert_file = request.files.get("certificate")
        if not doc or not doc.filename or not sig or not sig.filename or not cert_file or not cert_file.filename:
            flash("Select the document, signature (.sig), and certificate (.pem).", "error")
            return redirect(url_for("verify"))
        try:
            cert = x509.load_pem_x509_certificate(cert_file.read())
            public_key = cert.public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("The certificate does not contain an RSA public key.")
            public_key.verify(
                sig.read(), doc.read(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            result = ("valid", "Signature VALID", "The document matches the signature for the public key in this certificate.")
        except Exception:
            result = ("invalid", "Signature INVALID", "Verification failed. The document or signature may have changed, or the certificate may not match.")
    return render_template("verify.html", result=result)


@app.route("/download/signature/<path:filename>")
def download_signature(filename):
    path = UPLOADS / safe_name(filename)
    if not path.is_file():
        flash("Signature file not found. Sign the document again.", "error")
        return redirect(url_for("sign"))
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/download/certificate")
def download_certificate():
    ensure_identity()
    return send_file(CERT_PATH, as_attachment=True, download_name="certificate.pem")


@app.route("/certificate")
def certificate():
    ensure_identity()
    cert = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    details = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
    }
    return render_template("certificate.html", details=details)


if __name__ == "__main__":
    ensure_identity()
    app.run(debug=True)
