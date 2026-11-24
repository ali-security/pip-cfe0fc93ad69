"""Tests for the CA bundle shipped with pip's vendored certifi."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from pip._vendor import certifi

# SHA-256 fingerprints (over the DER encoding) of root certificates that
# Mozilla has distrusted and that must not be in the vendored CA bundle.
DISTRUSTED_ROOTS = {
    "Atos TrustedRoot 2011": (
        "f3:56:be:a2:44:b7:a9:1e:b3:5d:53:ca:9a:d7:86:4a"
        ":ce:01:8e:2d:35:d5:f8:f9:6d:df:68:a6:f4:1a:a4:74"
    ),
    "emSign ECC Root CA - G3": (
        "86:a1:ec:ba:08:9c:4a:8d:3b:be:27:34:c6:12:ba:34"
        ":1d:81:3e:04:3c:f9:e8:a8:62:cd:5c:57:a3:6b:be:6b"
    ),
}

# SHA-256 fingerprints of root certificates added to the bundle in the
# same Mozilla trust-store update.
ADDED_ROOTS = {
    "SECOM TLS RSA Root CA 2024": (
        "14:35:f2:25:c5:d2:52:d7:a2:19:48:cc:3c:e6:2a:ec"
        ":fa:88:00:1e:3d:d7:2d:1c:c3:55:51:00:eb:37:2f:93"
    ),
    "SECOM TLS ECC Root CA 2024": (
        "6a:b2:ab:75:f5:1c:b4:f4:f0:15:62:03:fb:f6:f6:46"
        ":23:2f:51:4b:e0:59:f6:28:33:30:8b:82:b4:d7:2d:b1"
    ),
    "Telia EC TLS Root CA v3": (
        "09:8e:08:a9:1d:bb:f7:74:78:b9:6c:ce:b8:9b:14:13"
        ":a5:da:37:b7:c8:62:60:6a:95:5d:eb:07:17:9f:43:26"
    ),
    "Telia RSA TLS Root CA v3": (
        "d1:3d:b1:29:4c:45:eb:c6:fc:86:c6:bb:f6:9f:a2:9b"
        ":df:e6:92:df:f7:c7:13:c2:43:c7:a9:56:c6:a2:28:4c"
    ),
}


def _normalize(fingerprint: str) -> str:
    return fingerprint.replace(":", "").lower()


@pytest.fixture(scope="module")
def bundle_fingerprints() -> set[str]:
    """SHA-256 fingerprints of every CA OpenSSL loads from certifi.where()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=certifi.where())
    return {
        hashlib.sha256(der).hexdigest()
        for der in ctx.get_ca_certs(binary_form=True)
    }


def test_bundle_loads_many_roots(bundle_fingerprints: set[str]) -> None:
    assert len(bundle_fingerprints) > 100


@pytest.mark.parametrize("name", sorted(DISTRUSTED_ROOTS))
def test_distrusted_root_not_trusted(bundle_fingerprints: set[str], name: str) -> None:
    assert _normalize(DISTRUSTED_ROOTS[name]) not in bundle_fingerprints


@pytest.mark.parametrize("name", sorted(DISTRUSTED_ROOTS))
def test_distrusted_root_not_listed(name: str) -> None:
    contents = certifi.contents()
    assert f'Label: "{name}"' not in contents
    assert DISTRUSTED_ROOTS[name] not in contents


@pytest.mark.parametrize("name", sorted(ADDED_ROOTS))
def test_added_root_trusted(bundle_fingerprints: set[str], name: str) -> None:
    assert _normalize(ADDED_ROOTS[name]) in bundle_fingerprints
