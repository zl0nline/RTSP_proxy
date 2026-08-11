import pytest

from rtsp_proxy.identifiers import InvalidPublicId, PublicId


def test_public_id_accepts_canonical_26_character_lowercase_base32() -> None:
    value = "a" * 26

    public_id = PublicId.parse(value)

    assert str(public_id) == value


@pytest.mark.parametrize(
    "value",
    [
        "a" * 25,
        "a" * 27,
        "A" * 26,
        "a" * 25 + "/",
        "a" * 25 + "?",
        "a" * 25 + "#",
        "a" * 25 + "0",
        "a" * 25 + "1",
        "a" * 25 + "8",
        "a" * 25 + "9",
        "a" * 25 + "b",
    ],
)
def test_public_id_rejects_noncanonical_or_route_mutating_values(value: str) -> None:
    with pytest.raises(InvalidPublicId, match="invalid_public_id"):
        PublicId.parse(value)

    with pytest.raises(InvalidPublicId, match="invalid_public_id"):
        PublicId(value)
