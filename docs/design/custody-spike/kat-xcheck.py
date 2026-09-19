# Usage: python3 docs/design/custody-spike/kat-xcheck.py  (needs pyca/cryptography)
# Expected output equals the constants in common/src/custody/tests.rs.
# Independent re-derivation of the custody KATs with pyca/cryptography.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
gk = Ed25519PrivateKey.from_private_bytes(bytes([0x42]*32))
st_seed = bytes([0x51]*32)
st = Ed25519PrivateKey.from_private_bytes(st_seed)
st_vk = st.public_key().public_bytes(*raw); gk_vk = gk.public_key().public_bytes(*raw)
scope = bytes([7]*32)
msg = b"harvest/store-key-wrap/v1\0" + st_vk
# ScopedPayload CBOR as ciborium emits it: map{requestor: {WebApp: [32 u8 array]}, payload: [u8 array]}
def cbor_uint(n, major=0):
    if n < 24: return bytes([(major<<5)|n])
    if n < 256: return bytes([(major<<5)|24, n])
    return bytes([(major<<5)|25]) + n.to_bytes(2,'big')
def arr(bs): return cbor_uint(len(bs),4) + b"".join(cbor_uint(b) for b in bs)
def txt(s): return cbor_uint(len(s),3) + s.encode()
scoped = cbor_uint(2,5) + txt("requestor") + cbor_uint(1,5) + txt("WebApp") + arr(scope) + txt("payload") + arr(msg)
sig = gk.sign(scoped)
print("scoped", scoped.hex())
print("sig", sig.hex())
okm = HKDF(hashes.SHA256(), 44, b"harvest/store-key-wrap/v1/hkdf-salt",
           b"harvest/store-key-wrap/v1/aes-256-gcm-key+nonce" + st_vk + gk_vk + scope).derive(sig)
aad = b"harvest/store-key-wrap/v1/aad" + bytes([1]) + st_vk + gk_vk + scope
print("wrapped", AESGCM(okm[:32]).encrypt(okm[32:], st_seed, aad).hex())
inbox = HKDF(hashes.SHA256(), 32, b"harvest/store-key/v1/subkeys", b"harvest/store-key/v1/inbox-x25519").derive(st_seed)
print("inbox_pub", X25519PrivateKey.from_private_bytes(inbox).public_key().public_bytes(*raw).hex())
