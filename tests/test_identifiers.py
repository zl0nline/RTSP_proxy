import pytest

from rtsp_proxy.identifiers import InvalidPublicId, PublicId


def test_public_id_accepts_the_canonical_25_character_base36_space() -> None:
    value = "a0" * 12 + "z"

    public_id = PublicId.parse(value)

    assert str(public_id) == value


@pytest.mark.parametrize(
    "value",
    [
        "a" * 24,
        "a" * 26,
        "A" * 25,
        "a" * 24 + "/",
        "a" * 24 + "?",
        "a" * 24 + "#",
    ],
)
def test_public_id_rejects_noncanonical_or_route_mutating_values(value: str) -> None:
    with pytest.raises(InvalidPublicId, match="invalid_public_id"):
        PublicId.parse(value)

    with pytest.raises(InvalidPublicId, match="invalid_public_id"):
        PublicId(value)
