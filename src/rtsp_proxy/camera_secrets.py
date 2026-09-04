from __future__ import annotations

import base64
import grp
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rtsp_proxy.probe_executor import probe_credential_component_valid

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True, slots=True)
class CameraSourceCredentials:
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        if not probe_credential_component_valid(self.username, maximum_bytes=64) or not (
            probe_credential_component_valid(self.password, maximum_bytes=256)
        ):
            raise ValueError("camera_source_credentials_invalid")


@dataclass(frozen=True, slots=True)
class CameraSourceSecretEnvelope:
    key_id: str
    ciphertext: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if _KEY_ID.fullmatch(self.key_id) is None or not 29 <= len(self.ciphertext) <= 1024:
            raise ValueError("camera_source_secret_invalid")


@dataclass(frozen=True, slots=True)
class CameraSourceKeyRing:
    primary_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        copied = dict(self.keys)
        if (
            _KEY_ID.fullmatch(self.primary_key_id) is None
            or self.primary_key_id not in copied
            or not 1 <= len(copied) <= 2
            or any(_KEY_ID.fullmatch(key_id) is None for key_id in copied)
            or any(len(key) != 32 for key in copied.values())
        ):
            raise ValueError("camera_source_keyring_invalid")
        object.__setattr__(self, "keys", MappingProxyType(copied))


class CameraSourceCredentialCipher:
    def __init__(self, keyring: CameraSourceKeyRing) -> None:
        self._keyring = keyring

    @property
    def primary_key_id(self) -> str:
        return self._keyring.primary_key_id

    def seal(
        self,
        camera_id: UUID,
        credentials: CameraSourceCredentials,
    ) -> CameraSourceSecretEnvelope:
        key_id = self._keyring.primary_key_id
        nonce = os.urandom(12)
        plaintext = json.dumps(
            {"password": credentials.password, "username": credentials.username},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        ciphertext = nonce + AESGCM(self._keyring.keys[key_id]).encrypt(
            nonce,
            plaintext,
            _associated_data(camera_id, key_id),
        )
        return CameraSourceSecretEnvelope(key_id=key_id, ciphertext=ciphertext)

    def open(
        self,
        camera_id: UUID,
        envelope: CameraSourceSecretEnvelope,
    ) -> CameraSourceCredentials:
        key = self._keyring.keys.get(envelope.key_id)
        if key is None:
            raise ValueError("camera_source_secret_key_unavailable")
        nonce, encrypted = envelope.ciphertext[:12], envelope.ciphertext[12:]
        try:
            plaintext = AESGCM(key).decrypt(
                nonce,
                encrypted,
                _associated_data(camera_id, envelope.key_id),
            )
            payload = json.loads(plaintext)
            if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
                raise ValueError
            username = payload["username"]
            password = payload["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError
            return CameraSourceCredentials(username=username, password=password)
        except (InvalidTag, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            raise ValueError("camera_source_secret_invalid") from None


def load_camera_source_cipher(
    path: str | os.PathLike[str],
    *,
    group_name: str = "rtsp-proxy-access",
) -> CameraSourceCredentialCipher:
    descriptor = -1
    try:
        expected_gid = grp.getgrnam(group_name).gr_gid
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or file_stat.st_uid != 0
            or file_stat.st_gid != expected_gid
            or stat.S_IMODE(file_stat.st_mode) != 0o640
            or not 1 <= file_stat.st_size <= 4096
        ):
            raise ValueError
        payload = os.read(descriptor, 4097)
        return CameraSourceCredentialCipher(parse_camera_source_keyring(payload.decode("utf-8")))
    except (KeyError, OSError, UnicodeError, ValueError):
        raise ValueError("camera_source_key_file_unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def parse_camera_source_keyring(value: str) -> CameraSourceKeyRing:
    try:
        payload = json.loads(value)
        if not isinstance(payload, dict) or set(payload) != {"primary_key_id", "keys"}:
            raise ValueError
        primary_key_id = payload["primary_key_id"]
        encoded_keys = payload["keys"]
        if not isinstance(primary_key_id, str) or not isinstance(encoded_keys, dict):
            raise ValueError
        keys: dict[str, bytes] = {}
        for key_id, encoded in encoded_keys.items():
            if not isinstance(key_id, str) or not isinstance(encoded, str):
                raise ValueError
            padding = "=" * (-len(encoded) % 4)
            keys[key_id] = base64.b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
        return CameraSourceKeyRing(primary_key_id=primary_key_id, keys=keys)
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("camera_source_keyring_invalid") from None


def attach_source_credentials(
    source_url: str,
    credentials: CameraSourceCredentials,
) -> str:
    try:
        parsed = urlsplit(source_url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("camera_source_url_invalid") from error
    if parsed.hostname is None or parsed.username is not None or parsed.password is not None:
        raise ValueError("camera_source_url_invalid")
    host = parsed.hostname
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port is None else f"{authority_host}:{port}"
    userinfo = f"{quote(credentials.username, safe='')}:{quote(credentials.password, safe='')}"
    return urlunsplit((parsed.scheme, f"{userinfo}@{authority}", parsed.path, parsed.query, ""))


def split_source_credentials(
    source_url: str,
) -> tuple[str, CameraSourceCredentials | None]:
    try:
        parsed = urlsplit(source_url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("camera_source_url_invalid") from error
    username = parsed.username
    password = parsed.password
    if (username is None) != (password is None) or parsed.hostname is None:
        raise ValueError("camera_source_credentials_invalid")
    host = parsed.hostname
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port is None else f"{authority_host}:{port}"
    clean = urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, parsed.fragment))
    credentials = (
        None
        if username is None
        else CameraSourceCredentials(username=unquote(username), password=unquote(password or ""))
    )
    return clean, credentials


def _associated_data(camera_id: UUID, key_id: str) -> bytes:
    return f"rtsp-proxy-camera-source-v1:{camera_id}:{key_id}".encode("ascii")
