import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rtsp_proxy.camera_secrets import (
    CameraSourceCredentialCipher,
    CameraSourceCredentials,
    CameraSourceSecretEnvelope,
    attach_source_credentials,
    load_camera_source_cipher,
    parse_camera_source_keyring,
    split_source_credentials,
)

CAMERA_ID = UUID("10000000-0000-4000-8000-000000000001")


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def test_camera_source_credentials_are_encrypted_versioned_and_rotation_readable() -> None:
    previous = b"p" * 32
    current = b"c" * 32
    keyring = parse_camera_source_keyring(
        json.dumps(
            {
                "primary_key_id": "2026-09",
                "keys": {
                    "2026-08": _encoded(previous),
                    "2026-09": _encoded(current),
                },
            }
        )
    )
    credentials = CameraSourceCredentials(
        username="operator@example",
        password="not-visible-in-repr",
    )
    cipher = CameraSourceCredentialCipher(keyring)

    sealed = cipher.seal(CAMERA_ID, credentials)

    assert sealed.key_id == "2026-09"
    assert credentials.username not in repr(credentials)
    assert credentials.password not in repr(credentials)
    assert credentials.password.encode() not in sealed.ciphertext
    assert cipher.open(CAMERA_ID, sealed) == credentials


def test_camera_source_credential_envelope_is_bound_to_camera_id() -> None:
    cipher = CameraSourceCredentialCipher(
        parse_camera_source_keyring(
            json.dumps(
                {
                    "primary_key_id": "2026-09",
                    "keys": {"2026-09": _encoded(b"c" * 32)},
                }
            )
        )
    )
    sealed = cipher.seal(
        CAMERA_ID,
        CameraSourceCredentials(username="operator", password="secret-value"),
    )

    with pytest.raises(ValueError, match="camera_source_secret_invalid"):
        cipher.open(UUID("20000000-0000-4000-8000-000000000002"), sealed)


def test_source_credentials_are_percent_encoded_into_a_runtime_only_url() -> None:
    assert attach_source_credentials(
        "rtsp://[2001:db8::5]:8554/live/main",
        CameraSourceCredentials(username="user@site", password="p:a/ss"),
    ) == "rtsp://user%40site:p%3Aa%2Fss@[2001:db8::5]:8554/live/main"


def test_camera_source_key_file_requires_exact_private_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "camera-source-keys.json"
    key_file.write_text(
        json.dumps(
            {
                "primary_key_id": "initial",
                "keys": {"initial": _encoded(b"k" * 32)},
            }
        ),
        encoding="utf-8",
    )
    key_file.chmod(0o640)
    real_fstat = os.fstat

    def trusted_stat(descriptor: int) -> SimpleNamespace:
        observed = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=observed.st_mode,
            st_nlink=1,
            st_uid=0,
            st_gid=54321,
            st_size=observed.st_size,
        )

    monkeypatch.setattr("rtsp_proxy.camera_secrets.os.fstat", trusted_stat)
    monkeypatch.setattr(
        "rtsp_proxy.camera_secrets.grp.getgrnam",
        lambda _name: SimpleNamespace(gr_gid=54321),
    )
    assert load_camera_source_cipher(key_file).primary_key_id == "initial"

    key_file.chmod(0o644)
    with pytest.raises(ValueError, match="camera_source_key_file_unsafe"):
        load_camera_source_cipher(key_file)


@pytest.mark.parametrize(
    ("username", "password"),
    (("", "secret"), ("operator", ""), ("x" * 65, "secret"), ("operator", "x" * 257)),
)
def test_camera_source_credentials_reject_invalid_components(
    username: str,
    password: str,
) -> None:
    with pytest.raises(ValueError, match="camera_source_credentials_invalid"):
        CameraSourceCredentials(username=username, password=password)


@pytest.mark.parametrize(
    "value",
    (
        "not-json",
        "[]",
        '{"primary_key_id":1,"keys":{}}',
        '{"primary_key_id":"current","keys":{"current":1}}',
        '{"primary_key_id":"missing","keys":{"current":"a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"}}',
    ),
)
def test_camera_source_keyring_rejects_malformed_documents(value: str) -> None:
    with pytest.raises(ValueError, match="camera_source_keyring_invalid"):
        parse_camera_source_keyring(value)


def test_camera_source_envelope_rejects_invalid_shape_and_unknown_key() -> None:
    with pytest.raises(ValueError, match="camera_source_secret_invalid"):
        CameraSourceSecretEnvelope(key_id="bad key id", ciphertext=b"x" * 29)
    cipher = CameraSourceCredentialCipher(
        parse_camera_source_keyring(
            json.dumps(
                {"primary_key_id": "current", "keys": {"current": _encoded(b"c" * 32)}}
            )
        )
    )
    with pytest.raises(ValueError, match="camera_source_secret_key_unavailable"):
        cipher.open(
            CAMERA_ID,
            CameraSourceSecretEnvelope(key_id="retired", ciphertext=b"x" * 29),
        )


@pytest.mark.parametrize(
    "plaintext",
    (b"[]", b'{"password":"secret","username":1}'),
)
def test_camera_source_cipher_rejects_authenticated_noncredential_payloads(
    plaintext: bytes,
) -> None:
    key = b"c" * 32
    key_id = "current"
    nonce = b"N" * 12
    cipher = CameraSourceCredentialCipher(
        parse_camera_source_keyring(
            json.dumps({"primary_key_id": key_id, "keys": {key_id: _encoded(key)}})
        )
    )
    envelope = CameraSourceSecretEnvelope(
        key_id=key_id,
        ciphertext=nonce
        + AESGCM(key).encrypt(
            nonce,
            plaintext,
            f"rtsp-proxy-camera-source-v1:{CAMERA_ID}:{key_id}".encode("ascii"),
        ),
    )

    with pytest.raises(ValueError, match="camera_source_secret_invalid"):
        cipher.open(CAMERA_ID, envelope)


def test_source_credentials_round_trip_and_reject_ambiguous_urls() -> None:
    clean, credentials = split_source_credentials(
        "rtsp://user%40site:p%3Aa%2Fss@[2001:db8::5]:8554/live/main?profile=1#fragment"
    )
    assert clean == "rtsp://[2001:db8::5]:8554/live/main?profile=1#fragment"
    assert credentials == CameraSourceCredentials(username="user@site", password="p:a/ss")
    assert split_source_credentials("rtsp://camera.example.test/live") == (
        "rtsp://camera.example.test/live",
        None,
    )

    for value in (
        "rtsp://user@camera.example.test/live",
        "rtsp://camera.example.test:invalid/live",
    ):
        with pytest.raises(ValueError):
            split_source_credentials(value)
    for value in (
        "rtsp://user:secret@camera.example.test/live",
        "rtsp://camera.example.test:invalid/live",
    ):
        with pytest.raises(ValueError, match="camera_source_url_invalid"):
            attach_source_credentials(
                value,
                CameraSourceCredentials(username="operator", password="secret"),
            )
