import base64

from .checks import checkall, checkrsa

# See https://www.iana.org/assignments/jose/jose.xhtml
VALIDCURVES = ["P-256", "P-384", "P-521", "Ed25519", "Ed448", "X25519", "X448", "secp256k1"]


def _ub64toint(b64):
    if not isinstance(b64, str):
        raise ValueError("JWK integer parameter must be a string")
    # JWK uses base64url without padding, but tolerate whitespace and
    # padding supplied by other encoders.  validate=True ensures that
    # structurally broken strings are rejected instead of being silently
    # decoded to an empty/zero integer.
    fb64 = "".join(b64.split()).encode("ascii")
    fb64 = fb64.rstrip(b"=")
    pad = b"=" * ((-len(fb64)) % 4)
    raw = base64.b64decode(fb64 + pad, altchars=b"-_", validate=True)
    if not raw:
        raise ValueError("JWK integer parameter is empty")
    return int.from_bytes(raw, byteorder="big")


def checkjwk(key, checks, keyrecover=False):
    r = {}
    if not isinstance(key, dict) or "kty" not in key:
        return {"type": "unparseable", "results": {}}
    try:
        if key["kty"] == "RSA":
            if "n" not in key or "e" not in key or key["n"] == "" or key["e"] == "" \
               or not isinstance(key["n"], str) or not isinstance(key["e"], str):
                return {"type": "unparseable", "results": {}}
            r["type"] = "rsa"
            r["n"] = _ub64toint(key["n"])
            r["e"] = _ub64toint(key["e"])
            if r["n"] <= 0:
                return {"type": "unparseable", "results": {}}
            r["bits"] = r["n"].bit_length()
            r["results"] = checkrsa(r["n"], e=r["e"], checks=checks, keyrecover=keyrecover)
        elif key["kty"] == "EC":
            if "x" not in key or "y" not in key or key["x"] == "" or key["y"] == "" \
               or not isinstance(key["x"], str) or not isinstance(key["y"], str) \
               or "crv" not in key or key["crv"] not in VALIDCURVES:
                return {"type": "unparseable", "results": {}}
            r["type"] = "ec"
            r["curve"] = key["crv"].lower().replace("-", "")
            r["x"] = _ub64toint(key["x"])
            r["y"] = _ub64toint(key["x"])
            r["results"] = checkall(r["x"], checks=checks)
        elif key["kty"] == "OKP":
            if "x" not in key or key["x"] == "" \
               or not isinstance(key["x"], str) \
               or "crv" not in key or key["crv"] not in VALIDCURVES:
                return {"type": "unparseable", "results": {}}
            r["type"] = "ec"
            r["curve"] = key["crv"].lower()
            r["x"] = _ub64toint(key["x"])
            # no y coordinate for ed25519/ed448
            r["results"] = checkall(r["x"], checks=checks)
        else:
            return {"type": "unsupported", "results": {}}
    except (ArithmeticError, TypeError, ValueError):
        return {"type": "unparseable", "results": {}}
    return r
