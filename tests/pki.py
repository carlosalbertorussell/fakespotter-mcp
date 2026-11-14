"""
Test PKI built at test time with ``cryptography`` (nothing is committed:
keys and certificates are throw-away and regenerated every run).

  - a self-signed root CA
  - a document-signing certificate issued by it
  - a TSA certificate issued by it (critical EKU id-kp-timeStamping)

Plus helpers that produce real PDFs (PyMuPDF), PAdES signatures (pyHanko)
and RFC 3161 responses from a local, offline TSA (pyHanko DummyTimeStamper).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
from dataclasses import dataclass
from functools import lru_cache

from asn1crypto import algos, keys as asn1_keys, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class Identity:
    cert: asn1_x509.Certificate
    key: asn1_keys.PrivateKeyInfo


@dataclass(frozen=True)
class TestPKI:
    root: Identity
    signer: Identity
    tsa: Identity


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeSpotter Test PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _to_asn1(cert: x509.Certificate, key: rsa.RSAPrivateKey) -> Identity:
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    der_key = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return Identity(asn1_x509.Certificate.load(der_cert), asn1_keys.PrivateKeyInfo.load(der_key))


def _issue(subject_cn, subject_key, issuer_name, issuer_key, *, ca=False, eku=None,
           not_before=None, not_after=None):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(days=1))
        .not_valid_after(not_after or now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=not ca, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                       critical=False)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


@lru_cache(maxsize=1)
def test_pki() -> TestPKI:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = _name("FakeSpotter Test Root CA")
    root_cert = _issue("FakeSpotter Test Root CA", root_key, root_name, root_key, ca=True)

    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_cert = _issue("Test Supplier SA", signer_key, root_name, root_key)

    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_cert = _issue("FakeSpotter Test TSA", tsa_key, root_name, root_key,
                      eku=[ExtendedKeyUsageOID.TIME_STAMPING])

    return TestPKI(
        root=_to_asn1(root_cert, root_key),
        signer=_to_asn1(signer_cert, signer_key),
        tsa=_to_asn1(tsa_cert, tsa_key),
    )


@lru_cache(maxsize=1)
def expired_signer() -> Identity:
    """A document-signing certificate from the test root whose validity ended 30 days ago."""
    pki = test_pki()
    root_key = serialization.load_der_private_key(pki.root.key.dump(), password=None)
    root_name = x509.load_der_x509_certificate(pki.root.cert.dump()).subject
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _issue("Expired Supplier SA", key, root_name, root_key,
                  not_before=now - dt.timedelta(days=400),
                  not_after=now - dt.timedelta(days=30))
    return _to_asn1(cert, key)


# Pytest would otherwise try to collect the factory and the dataclass.
test_pki.__test__ = False  # type: ignore[attr-defined]
TestPKI.__test__ = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# PDFs and signatures
# ---------------------------------------------------------------------------

TAMPER_MARK = b"FS-INVOICE-TOTAL-1234.56"


def make_pdf(text: str = "INVOICE 0001 - Total: USD 1,234.56") -> bytes:
    """One-page PDF whose Info /Subject holds TAMPER_MARK in plain bytes."""
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    doc.set_metadata({"subject": TAMPER_MARK.decode()})
    data = doc.tobytes()
    doc.close()
    return data


def _timestamper():
    from pyhanko.sign.timestamps import DummyTimeStamper
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    pki = test_pki()
    return DummyTimeStamper(
        tsa_cert=pki.tsa.cert, tsa_key=pki.tsa.key,
        certs_to_embed=SimpleCertificateStore.from_certs([pki.root.cert]),
    )


def sign_pdf(pdf: bytes, *, with_timestamp: bool = False, identity: Identity | None = None) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    pki = test_pki()
    identity = identity or pki.signer
    signer = signers.SimpleSigner(
        signing_cert=identity.cert, signing_key=identity.key,
        cert_registry=SimpleCertificateStore.from_certs([pki.root.cert]),
    )
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    out = signers.sign_pdf(
        writer, signers.PdfSignatureMetadata(field_name="Signature1"), signer=signer,
        timestamper=_timestamper() if with_timestamp else None,
    )
    return out.getvalue()


def tamper_signed_content(signed_pdf: bytes) -> bytes:
    """Change the invoice total inside the signed byte range.

    Same length, so every xref offset stays valid and the PDF still parses;
    only the signed digest no longer matches.
    """
    assert signed_pdf.count(TAMPER_MARK) == 1
    return signed_pdf.replace(TAMPER_MARK, TAMPER_MARK.replace(b"1234", b"9234"))


# ---------------------------------------------------------------------------
# RFC 3161
# ---------------------------------------------------------------------------

def make_tsr(document: bytes) -> bytes:
    """A granted TimeStampResp from the local TSA over SHA-256(document)."""
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": hashlib.sha256(document).digest(),
        }),
        "nonce": 0x5EED,
        "cert_req": True,
    })
    resp = _timestamper().request_tsa_response(req)
    return resp.dump()
