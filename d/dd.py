pip install cryptography
import base64, hashlib, json, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

b2i  = lambda s: int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

jwk = json.load(open("private.jwk.json"))
n, e, d, p, q = (b2i(jwk[k]) for k in ("n", "e", "d", "p", "q"))
dp = b2i(jwk["dp"]) if "dp" in jwk else rsa.rsa_crt_dmp1(d, p)
dq = b2i(jwk["dq"]) if "dq" in jwk else rsa.rsa_crt_dmq1(d, q)   # absent dans ton exemple
qi = b2i(jwk["qi"]) if "qi" in jwk else rsa.rsa_crt_iqmp(p, q)
key = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, rsa.RSAPublicNumbers(e, n)).private_key()
assert key.key_size >= 2048, "le gateway exige RSA >= 2048 bits"

name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "claude-gateway")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256()))

open("idp-client.key", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open("idp-client.crt", "wb").write(cert.public_bytes(serialization.Encoding.PEM))

der = cert.public_bytes(serialization.Encoding.DER)
print(json.dumps({"keys": [{
    "kty": "RSA", "use": "sig", "alg": "RS256", "kid": jwk.get("kid"),
    "n": jwk["n"], "e": jwk["e"],
    "x5t": b64u(hashlib.sha1(der).digest()),
    "x5t#S256": b64u(hashlib.sha256(der).digest()),
    "x5c": [base64.b64encode(der).decode()],
}]}, indent=2))
