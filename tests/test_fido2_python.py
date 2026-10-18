"""Cross-check the emulated FIDO2 authenticator against Yubico's python-fido2.

keepassxcr's FIDO2 client is tested against its own emulated authenticator
(src/fido2). Here python-fido2, an independent CTAP2 client, drives the same
emulator: if both clients agree with it on CBOR, the PIN protocols and
hmac-secret, keepassxcr speaks the protocol as real keys expect.

Skipped unless python-fido2 is installed (it is in the tests' uv project).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess

import pytest

from test_cli_compat import PROJECT_ROOT

fido2 = pytest.importorskip("fido2")

from fido2.ctap import CtapDevice  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2  # noqa: E402
from fido2.hid import CAPABILITY, CTAPHID  # noqa: E402
from fido2.webauthn import AuthenticatorData  # noqa: E402

SECRET = bytes(range(32))
RP_ID = "keepassxcr"


@pytest.fixture(scope="session")
def bridge_binary():
    target = PROJECT_ROOT / "target" / "fido2-bridge"
    subprocess.run(
        [
            "cargo",
            "build",
            "--example",
            "fido2_bridge",
            "--features",
            "software-fido2",
            "--target-dir",
            str(target),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        timeout=600,
    )
    return target / "debug" / "examples" / "fido2_bridge"


class BridgeDevice(CtapDevice):
    """A python-fido2 device backed by the emulator over a pipe."""

    def __init__(self, binary, pin: str | None, legacy: bool):
        args = [str(binary), SECRET.hex(), pin or "", "v1" if legacy else ""]
        self.proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        self.touches = 0

    @property
    def capabilities(self):
        return CAPABILITY.CBOR

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        self.proc.stdin.write(f"{cmd:02x} {bytes(data).hex()}\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline().strip()
            if line == "K":
                self.touches += 1
                if on_keepalive:
                    on_keepalive(2)
                continue
            kind, answer_cmd, answer = (line.split(" ") + [""])[:3]
            assert kind == "R" and int(answer_cmd, 16) == cmd, line
            return bytes.fromhex(answer)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)

    @classmethod
    def list_devices(cls):
        return iter(())


def expected_secret(credential_id: bytes, salt: bytes, uv: bool) -> bytes:
    """What the emulator documents: HMAC(HMAC(secret, uv-tag || id), salt)."""
    cred_random = hmac.new(SECRET, (b"uv" if uv else b"nu") + credential_id, hashlib.sha256).digest()
    return hmac.new(cred_random, salt, hashlib.sha256).digest()


CASES = [
    pytest.param(protocol, pin, legacy, id=f"{protocol.__name__}-{'pin' if pin else 'nopin'}{'-ctap20' if legacy else ''}")
    for protocol, legacy in ((PinProtocolV2, False), (PinProtocolV1, False), (PinProtocolV1, True))
    for pin in ("1234", None)
]


@pytest.mark.parametrize(("protocol_class", "pin", "legacy"), CASES)
def test_python_fido2_gets_the_documented_hmac_secret(bridge_binary, protocol_class, pin, legacy):
    device = BridgeDevice(bridge_binary, pin, legacy)
    try:
        ctap = Ctap2(device)
        assert "hmac-secret" in ctap.info.extensions
        assert ctap.info.options.get("clientPin") == (pin is not None)
        protocol = protocol_class()
        client_pin = ClientPin(ctap, protocol)

        token = None
        if pin:
            permissions = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
            token = client_pin.get_pin_token(pin, permissions, RP_ID)

        cdh = os.urandom(32)
        attestation = ctap.make_credential(
            cdh,
            {"id": RP_ID, "name": RP_ID},
            {"id": b"user", "name": "user"},
            [{"type": "public-key", "alg": -7}],
            extensions={"hmac-secret": True},
            options={"rk": False},
            pin_uv_param=protocol.authenticate(token, cdh) if token else None,
            pin_uv_protocol=protocol.VERSION if token else None,
        )
        auth_data = attestation.auth_data
        assert auth_data.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()
        assert auth_data.extensions == {"hmac-secret": True}
        credential_id = auth_data.credential_data.credential_id

        for uv in ([True, False] if token else [False]):
            salt = os.urandom(32)
            key_agreement, shared = client_pin._get_shared_secret()
            salt_enc = protocol.encrypt(shared, salt)
            extension = {1: key_agreement, 2: salt_enc, 3: protocol.authenticate(shared, salt_enc)}
            if protocol.VERSION == 2:
                extension[4] = 2
            cdh = os.urandom(32)
            assertion = ctap.get_assertion(
                RP_ID,
                cdh,
                [{"type": "public-key", "id": credential_id}],
                extensions={"hmac-secret": extension},
                pin_uv_param=protocol.authenticate(token, cdh) if uv else None,
                pin_uv_protocol=protocol.VERSION if uv else None,
            )
            data = AuthenticatorData(assertion.auth_data)
            assert data.is_user_present()
            assert data.is_user_verified() == uv
            output = protocol.decrypt(shared, data.extensions["hmac-secret"])
            assert output == expected_secret(credential_id, salt, uv)

        # A wrong PIN is refused and counted.
        if pin:
            with pytest.raises(Exception):
                client_pin.get_pin_token("0000", ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
            assert client_pin.get_pin_retries()[0] == 7
        assert device.touches >= 2
    finally:
        device.close()
