"""cursed_crypto: batch (multi-buffer) verification for pyca/cryptography's key objects, backed by cursed-crypto.

A companion to pyca/cryptography, not a replacement and not a backend: it takes pyca's public key objects and the
same bytes-like inputs, raises pyca's own ``cryptography.exceptions.InvalidSignature``, and gives every item the
verdict pyca's single ``verify`` would give it.  What it adds is one call for many items::

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import cursed_crypto

    v = cursed_crypto.ECDSAVerifier(public_key, ec.ECDSA(hashes.SHA256()))   # build once: key setup is the cost
    v.verify(signature, data)                     # None, or raises InvalidSignature (as public_key.verify)
    oks = v.verify_batch(signatures, datas)       # [True, False, ...]: one verdict per item

Batches are **per item**: each result is exactly what ``public_key.verify`` would decide for that item.  This is
not "all valid or not" batch verification (as in ed25519-dalek's ``verify_batch``), and one bad item never changes
another item's result.

Handled natively (everything else is passed to pyca, with pyca's result):

    Ed25519Verifier  Ed25519 (RFC 8032)
    ECDSAVerifier    ECDSA P-256 (SECP256R1) with SHA-256; DER signatures as pyca takes them, or raw r || s
    RSAVerifier      RSASSA-PKCS1-v1_5 with SHA-256, 2048 to 4096-bit moduli, odd 3 <= e < 2**64
    HMACSHA256       HMAC-SHA256 with 32-byte tags, any key; plus digest / digest_batch (MACs: HS256 signing)
    Ed25519Signer    Ed25519 signing for an Ed25519PrivateKey: sign / sign_batch, deterministic (RFC 8032), constant
                     time in the private key; signatures byte-identical to the key's own sign()
    sha256_batch     SHA-256 of many messages

Other curves, hashes or paddings (PSS), RSA keys outside that range, ``Prehashed``, truncated HMAC tags, and any
key cursed-crypto refuses at setup are delegated to pyca/cryptography, inside a batch too.

Cost model: a verifier object owns cursed-crypto's per-key tables (ECDSA P-256: 528 KB, Ed25519: 568 KB, built in
about a millisecond; RSA: Montgomery constants).  Build one per key and keep it; don't build one per call.  There
are no module-level ``verify(public_key, ...)`` helpers: pyca's key objects can't be weakly referenced or hashed,
so a cache keyed by them could only keep keys alive or recompute their identity on every call.

Errors: an item that isn't bytes-like raises ``TypeError`` (as pyca does) for the whole batch, before anything is
verified; ``signatures`` and ``datas`` of different lengths raise ``ValueError``.

The GIL is released while cursed-crypto runs (key setup, every signature verify, every batch, and single HMACs of
2 KB or more), so threads that verify in parallel scale as with pyca.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import _native

__all__ = [
    "Ed25519Verifier",
    "ECDSAVerifier",
    "RSAVerifier",
    "HMACSHA256",
    "Ed25519Signer",
    "sha256_batch",
    "engine",
    "InvalidSignature",
]
__version__ = "0.1.0"

Buffer = bytes  # any bytes-like object (bytes, bytearray, memoryview, ...), as pyca takes


def engine() -> str:
    """The HMAC-SHA256 engine cursed-crypto picked for this CPU ("shani", "zmm", "avx512vl", "avx2", ...)."""
    return _native.engine()


def sha256_batch(datas: Iterable[Buffer]) -> List[bytes]:
    """SHA-256 digests (32 bytes each) of every item of ``datas``, hashed together."""
    return _native.sha256_batch(datas)


_PKCS1v15 = padding.PKCS1v15  # (RSAVerifier's argument is called padding, as in pyca)


def _seq(x: Iterable[Buffer]) -> Sequence[Buffer]:
    # iterated twice where items go to pyca, so an iterator is materialised first (a list or tuple is used as is)
    return x if type(x) in (list, tuple) else list(x)


def _pyca_type(obj: object) -> bool:
    # pyca's own key classes; an application's own subclass of pyca's abstract key types keeps its own verify()
    return type(obj).__module__.startswith("cryptography.")


class _Verifier:
    """Shared batch logic: ``self._k`` is a native key or None (everything for pyca), ``self._one`` pyca's verdict."""

    _k: Optional[_native.PKey]
    _der = False

    def _one(self, signature: Buffer, data: Buffer) -> bool:
        raise NotImplementedError

    def verify(self, signature: Buffer, data: Buffer) -> None:
        """As the pyca key's ``verify``: returns None, or raises ``InvalidSignature``."""
        k = self._k
        if k is not None:
            r = k.verify(signature, data, self._der)
            if r is True:
                return None
            if r is False:
                raise InvalidSignature
        if not self._one(signature, data):
            raise InvalidSignature
        return None

    def verify_batch(self, signatures: Iterable[Buffer], datas: Iterable[Buffer]) -> List[bool]:
        """One verdict per item: ``True`` where ``verify(signatures[i], datas[i])`` would return, ``False`` where it
        would raise ``InvalidSignature``."""
        k = self._k
        signatures, datas = _seq(signatures), _seq(datas)
        if k is None:
            if len(signatures) != len(datas):
                raise ValueError(f"signatures and datas have different lengths ({len(signatures)} and {len(datas)})")
            for x in (*signatures, *datas):
                memoryview(x)  # TypeError before verifying anything, as on the native path
            return [self._one(s, d) for s, d in zip(signatures, datas)]
        res, left = k.verify_batch(signatures, datas, self._der)
        if left:
            for i, r in enumerate(res):
                if r is None:
                    res[i] = self._one(signatures[i], datas[i])
        return res


class Ed25519Verifier(_Verifier):
    """Ed25519 verification for an ``Ed25519PublicKey``.  ``verify(signature, data)`` as ``public_key.verify``."""

    def __init__(self, public_key: ed25519.Ed25519PublicKey) -> None:
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise TypeError("public_key must be an Ed25519PublicKey")
        self.public_key = public_key
        # None where the key doesn't decode to a point: pyca decides those
        self._k = _native.pkey_ed25519(public_key.public_bytes_raw()) if _pyca_type(public_key) else None

    def _one(self, signature: Buffer, data: Buffer) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


class ECDSAVerifier(_Verifier):
    """ECDSA verification for an ``EllipticCurvePublicKey``, as ``public_key.verify(signature, data,
    signature_algorithm)``.

    ``signature_format="der"`` (the default) takes DER signatures, as pyca does.  ``"raw"`` takes r || s, each
    big-endian and padded to the curve's byte length (IEEE P1363, as in JWS ES256): such a signature is valid
    exactly when pyca accepts ``encode_dss_signature(r, s)``, and any other length is invalid.

    Native for SECP256R1 with ``ec.ECDSA(hashes.SHA256())``; any other curve or hash goes to pyca."""

    def __init__(
        self,
        public_key: ec.EllipticCurvePublicKey,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
        *,
        signature_format: str = "der",
    ) -> None:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise TypeError("public_key must be an EllipticCurvePublicKey")
        if not isinstance(signature_algorithm, ec.EllipticCurveSignatureAlgorithm):
            raise TypeError("signature_algorithm must be an EllipticCurveSignatureAlgorithm, e.g. ec.ECDSA(SHA256())")
        if signature_format not in ("der", "raw"):
            raise ValueError('signature_format must be "der" or "raw"')
        self.public_key = public_key
        self.signature_algorithm = signature_algorithm
        self.signature_format = signature_format
        self._der = signature_format == "der"
        self._clen = (public_key.curve.key_size + 7) // 8
        self._k = None
        if (
            _pyca_type(public_key)
            and isinstance(public_key.curve, ec.SECP256R1)
            and type(signature_algorithm) is ec.ECDSA
            and type(signature_algorithm.algorithm) is hashes.SHA256
        ):
            nums = public_key.public_numbers()
            self._k = _native.pkey_es256(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))

    def _one(self, signature: Buffer, data: Buffer) -> bool:
        if not self._der:
            sig = memoryview(signature).tobytes()
            if len(sig) != 2 * self._clen:
                return False
            r, s = int.from_bytes(sig[: self._clen], "big"), int.from_bytes(sig[self._clen :], "big")
            signature = encode_dss_signature(r, s)
        try:
            self.public_key.verify(signature, data, self.signature_algorithm)
            return True
        except InvalidSignature:
            return False


class RSAVerifier(_Verifier):
    """RSA verification for an ``RSAPublicKey``, as ``public_key.verify(signature, data, padding, algorithm)``.

    Native for ``padding.PKCS1v15()`` with ``hashes.SHA256()`` and 2048 to 4096-bit keys; PSS, other hashes,
    ``Prehashed`` and other key sizes go to pyca."""

    def __init__(
        self,
        public_key: rsa.RSAPublicKey,
        padding: padding.AsymmetricPadding,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("public_key must be an RSAPublicKey")
        self.public_key = public_key
        self.padding = padding
        self.algorithm = algorithm
        self._k = None
        if (
            _pyca_type(public_key)
            and type(padding) is _PKCS1v15
            and type(algorithm) is hashes.SHA256
            and 2048 <= public_key.key_size <= 4096
        ):
            nums = public_key.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes(max(1, (nums.e.bit_length() + 7) // 8), "big")
            self._k = _native.pkey_rs256(n, e)  # None for e < 3, e >= 2**64 or an even e or n: pyca decides

    def _one(self, signature: Buffer, data: Buffer) -> bool:
        try:
            self.public_key.verify(signature, data, self.padding, self.algorithm)
            return True
        except InvalidSignature:
            return False


class HMACSHA256:
    """HMAC-SHA256 under one key, as pyca's ``hmac.HMAC(key, hashes.SHA256())`` used one-shot.

    ``verify(data, signature)`` returns None or raises ``InvalidSignature`` like ``h.update(data); h.verify(sig)``;
    ``verify_batch(datas, signatures)`` gives one verdict per item.  Tags are compared in constant time inside
    cursed-crypto (``cc_hmac_sha256_verify``), never in Python.  A tag that isn't 32 bytes (pyca rejects every
    truncated tag) is passed to pyca.  The key's SHA-256 midstates live in the C object; the key bytes are kept
    only for those delegated items.  There is no streaming ``update()``: batches are one-shot."""

    def __init__(self, key: Buffer) -> None:
        hmac.HMAC(key, hashes.SHA256())  # pyca's own checks on the key first, so errors are pyca's
        self._key = memoryview(key).tobytes()
        self._k = _native.HMACKey(self._key)

    def _one(self, data: Buffer, signature: Buffer) -> bool:
        h = hmac.HMAC(self._key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(signature)
            return True
        except InvalidSignature:
            return False

    def digest(self, data: Buffer) -> bytes:
        """The 32-byte MAC of ``data``."""
        return self._k.digest(data)

    def digest_batch(self, datas: Iterable[Buffer]) -> List[bytes]:
        """The 32-byte MACs of every item of ``datas``, computed together."""
        return self._k.digest_batch(datas)

    def verify(self, data: Buffer, signature: Buffer) -> None:
        r = self._k.verify(data, signature)
        if r is None:
            r = self._one(data, signature)
        if not r:
            raise InvalidSignature

    def verify_batch(self, datas: Iterable[Buffer], signatures: Iterable[Buffer]) -> List[bool]:
        datas, signatures = _seq(datas), _seq(signatures)
        res, left = self._k.verify_batch(datas, signatures)
        if left:
            for i, r in enumerate(res):
                if r is None:
                    res[i] = self._one(datas[i], signatures[i])
        return res


class Ed25519Signer:
    """Ed25519 signing for an ``Ed25519PrivateKey``: ``sign(data)`` as ``private_key.sign(data)``, and
    ``sign_batch(datas)`` for many messages in one call.  Ed25519 is deterministic (RFC 8032), so every signature is
    byte-identical to the one pyca's ``private_key.sign`` returns.

    The native path is cursed-crypto's constant-time signer: no branch or memory address depends on the private key
    or the per-signature nonce.  It holds its own copy of the key (about 30 KB with a table of multiples of the base
    point, built in about 0.1 ms) and wipes it when the signer is garbage-collected.  Getting the key out of pyca
    goes through ``private_bytes_raw()``, whose ``bytes`` copy Python can't wipe; it is dropped at once.  A key
    object that isn't pyca's own class (a subclass with its own ``sign``) is used through its ``sign``.

    Errors: an item that isn't bytes-like raises ``TypeError`` for the whole batch, before anything is signed."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self.private_key = private_key
        self._k: Optional[_native.SKey] = None
        if _pyca_type(private_key):
            k = _native.skey_ed25519(private_key.private_bytes_raw())
            if k.public_bytes() != private_key.public_key().public_bytes_raw():
                raise RuntimeError("cursed_crypto: the derived Ed25519 public key differs from pyca's")
            self._k = k

    def public_key(self) -> ed25519.Ed25519PublicKey:
        """The key's public key, as ``private_key.public_key()``."""
        return self.private_key.public_key()

    def sign(self, data: Buffer) -> bytes:
        """The 64-byte signature of ``data``, as ``private_key.sign(data)``."""
        if self._k is None:
            return self.private_key.sign(data)
        return self._k.sign(data)

    def sign_batch(self, datas: Iterable[Buffer]) -> List[bytes]:
        """The 64-byte signatures of every item of ``datas``, signed together."""
        if self._k is None:
            datas = _seq(datas)
            for x in datas:
                memoryview(x)  # TypeError before signing anything, as on the native path
            return [self.private_key.sign(d) for d in datas]
        return self._k.sign_batch(datas)
