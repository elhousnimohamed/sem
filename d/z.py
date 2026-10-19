
import base64
import hashlib
import json
import os
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# --------------------------------------------------
# Helpers Base64URL pour les paramètres JWK
# --------------------------------------------------

def b64u_decode(value: str) -> int:
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(
        base64.urlsafe_b64decode(value + padding),
        "big",
    )


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


# --------------------------------------------------
# 1. Charger le JWK privé
# --------------------------------------------------

with open("private.jwk.json", "r", encoding="utf-8") as f:
    jwk = json.load(f)

required = ("n", "e", "d", "p", "q")
missing = [name for name in required if name not in jwk]

if missing:
    raise ValueError(f"Paramètres JWK manquants : {missing}")

n, e, d, p, q = (b64u_decode(jwk[k]) for k in required)

# Paramètres CRT : calculés s'ils sont absents.
dp = b64u_decode(jwk["dp"]) if "dp" in jwk else rsa.rsa_crt_dmp1(d, p)
dq = b64u_decode(jwk["dq"]) if "dq" in jwk else rsa.rsa_crt_dmq1(d, q)
qi = b64u_decode(jwk["qi"]) if "qi" in jwk else rsa.rsa_crt_iqmp(p, q)

# Reconstruire et valider la clé RSA.
key = rsa.RSAPrivateNumbers(
    p=p,
    q=q,
    d=d,
    dmp1=dp,
    dmq1=dq,
    iqmp=qi,
    public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
).private_key()

if key.key_size < 2048:
    raise ValueError("Le gateway exige une clé RSA d'au moins 2048 bits.")

print(f"Clé RSA chargée : {key.key_size} bits")


# --------------------------------------------------
# 2. Générer le certificat auto-signé
# --------------------------------------------------

now = datetime.datetime.now(datetime.timezone.utc)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "claude-gateway")
])

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256())
)

# Vérification : le certificat et la clé privée doivent
# exposer exactement la même clé publique.
if cert.public_key().public_numbers() != key.public_key().public_numbers():
    raise ValueError("Le certificat ne correspond pas à la clé privée.")

print("Vérification certificat / clé privée : OK")


# --------------------------------------------------
# 3. Écrire la clé privée et le certificat
# --------------------------------------------------

key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

cert_pem = cert.public_bytes(serialization.Encoding.PEM)

with open("idp-client.key", "wb") as f:
    f.write(key_pem)

with open("idp-client.crt", "wb") as f:
    f.write(cert_pem)

# Permissions restrictives sur la clé privée (systèmes POSIX).
if os.name == "posix":
    os.chmod("idp-client.key", 0o600)


# --------------------------------------------------
# 4. Générer le JWKS public
# --------------------------------------------------

der = cert.public_bytes(serialization.Encoding.DER)

# Vérifier que n et e du JWK source correspondent
# à la clé reconstruite.
public_numbers = key.public_key().public_numbers()

if public_numbers.n != n or public_numbers.e != e:
    raise ValueError("Les paramètres publics n/e ne correspondent pas.")

# Utiliser le kid existant s'il est fourni ; sinon en générer un
# stable pour cette clé publique.
kid = jwk.get("kid")
if not kid:
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = b64u_encode(hashlib.sha256(public_der).digest()[:16])

jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": jwk["n"],
            "e": jwk["e"],
            "x5t": b64u_encode(hashlib.sha1(der).digest()),
            "x5t#S256": b64u_encode(hashlib.sha256(der).digest()),
            "x5c": [base64.b64encode(der).decode("ascii")],
        }
    ]
}

with open("jwks.json", "w", encoding="utf-8") as f:
    json.dump(jwks, f, indent=2)
    f.write("\n")


# --------------------------------------------------
# 5. Résumé
# --------------------------------------------------

print("Fichiers générés :")
print(" - idp-client.key")
print(" - idp-client.crt")
print(" - jwks.json")
print(f"kid : {kid}")
print(f"SHA-256 du certificat : {b64u_encode(hashlib.sha256(der).digest())}")
