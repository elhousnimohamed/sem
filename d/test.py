# pip install pyjwt cryptography requests
import base64, hashlib, time, uuid, jwt, requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
der = x509.load_pem_x509_certificate(open("idp-client.crt","rb").read()).public_bytes(serialization.Encoding.DER)
X5T, X5T2 = b64u(hashlib.sha1(der).digest()), b64u(hashlib.sha256(der).digest())
key = open("idp-client.key").read()
KID = "<kid complet de ta clé IAs6P..., copié du GET>"
cid = "6ymx6w322f"
tok = "https://onelogin.dev.axa.com/as/token.oauth2"
iss = "https://onelogin.dev.axa.com"
cb = "<public_url de ta conf>/oauth/callback"
heads = {"x5t (comme la gateway)": {"x5t": X5T, "x5t#S256": X5T2},
         "kid": {"kid": KID}, "kid+x5t": {"kid": KID, "x5t": X5T, "x5t#S256": X5T2}, "aucun": {}}
for hn, h in heads.items():
    for an, aud in {"token_url": tok, "issuer": iss}.items():
        now = int(time.time())
        a = jwt.encode({"iss": cid, "sub": cid, "aud": aud, "jti": str(uuid.uuid4()),
                        "iat": now, "exp": now + 60}, key, algorithm="RS256", headers=h)
        r = requests.post(tok, timeout=20, data={"grant_type": "authorization_code",
            "code": "dummy", "redirect_uri": cb, "client_id": cid,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": a})
        print(hn, "|", an, "|", r.status_code, r.text[:120])
