"""google-play-scraper turns certificate verification off for the whole process.

google_play_scraper/utils/request.py (1.2.7) runs, when it is imported,
`ssl._create_default_https_context = ssl._create_unverified_context`. urllib takes
that default for every HTTPS request it opens, so from the first Play Store lookup
on, any certificate was accepted: the Play Store page, whose developer website
ApkRadar takes as the publisher's domain, could be rewritten by anyone on the path.
ApkRadar's own requests, and its dependencies', go through httpx, which builds its
own context and is not affected; nothing else in the process uses urllib.

search_cmd imports the scraper through `_import_play_scraper`, which puts the
default back as soon as the import returns. The module runs once per process, so
nothing switches it off again.

Each check runs in a fresh interpreter, because the side effect happens once per
process. The server is a real TLS server on 127.0.0.1 with a certificate made here
and trusted by nobody: a verifying client refuses it, an unverified one reads it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

SERVER = textwrap.dedent(
    """
    import datetime, ipaddress, os, ssl, tempfile, threading, urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    folder = tempfile.mkdtemp()
    certfile, keyfile = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))

    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"reached")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Page)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    URL = "https://127.0.0.1:%d/" % server.server_address[1]

    def fetch():
        try:
            return urllib.request.urlopen(URL, timeout=10).read().decode()
        except Exception as error:
            return type(getattr(error, "reason", error)).__name__
    """
)


def _fetch_after(statements: str) -> str:
    code = SERVER + "\n" + textwrap.dedent(statements) + "\nprint(fetch())\n"
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip().splitlines()[-1]


def test_a_verifying_client_refuses_the_local_server():
    """The baseline: the server is untrusted, and urllib says so."""
    assert _fetch_after("") == "SSLCertVerificationError"


def test_the_scraper_alone_turns_verification_off():
    """The side effect is real, so the next test cannot pass for nothing."""
    assert _fetch_after("import google_play_scraper") == "reached"


def test_apkradar_imports_the_scraper_and_keeps_verification_on():
    assert _fetch_after(
        """
        from apkradar.search_cmd import _import_play_scraper
        app, not_found = _import_play_scraper()
        assert callable(app) and issubclass(not_found, Exception)
        """
    ) == "SSLCertVerificationError"
