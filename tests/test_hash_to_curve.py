import pytest
from hypothesis import given, strategies as st
from src.ecc import HashToCurve

# RFC 9380 Appendix K.1
test_vectors = [
    {
        "msg": "",
        "len_in_bytes": 0x20,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f8"
            "7f7a21d803f07235"
        ),
    },
    {
        "msg": "abc",
        "len_in_bytes": 0x20,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b979"
            "02f53a8a0d605615"
        ),
    },
    {
        "msg": "abcdef0123456789",
        "len_in_bytes": 0x20,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2c"
            "b4eafe524333f5c1"
        ),
    },
    {
        "msg": "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        "qqqqqqqqqqqqqqqqqqqqqqqqq",
        "len_in_bytes": 0x20,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa5"
            "1bfe3f12ddad1ff9"
        ),
    },
    {
        "msg": "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "len_in_bytes": 0x20,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "4623227bcc01293b8c130bf771da8c298dede7383243dc09"
            "93d2d94823958c4c"
        ),
    },
    {
        "msg": "",
        "len_in_bytes": 0x80,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac0"
            "6d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4"
            "cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec8"
            "49469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472"
            "c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
        ),
    },
    {
        "msg": "abc",
        "len_in_bytes": 0x80,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2"
            "fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b"
            "664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221"
            "b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425"
            "cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
        ),
    },
    {
        "msg": "abcdef0123456789",
        "len_in_bytes": 0x80,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d6"
            "29831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f"
            "0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f8"
            "7910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7d"
            "e2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"
        ),
    },
    {
        "msg": "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        "qqqqqqqqqqqqqqqqqqqqqqqqq",
        "len_in_bytes": 0x80,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a"
            "5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169"
            "761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b3"
            "2286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520e"
            "e603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"
        ),
    },
    {
        "msg": "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "len_in_bytes": 0x80,
        "DST": b"QUUX-V01-CS02-with-expander-SHA256-128",
        "uniform_bytes": bytes.fromhex(
            "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9"
            "e75885cad9def1d06d6792f8a7d12794e90efed817d96920d72889"
            "6a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4cee"
            "f777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43"
            "d98a294bebb9125d5b794e9d2a81181066eb954966a487"
        ),
    },
]


@pytest.mark.parametrize("vector", test_vectors)
def test_expand_message_xmd(vector: dict) -> None:
    msg = vector["msg"].encode("utf-8")
    len_in_bytes = vector["len_in_bytes"]
    DST = vector["DST"]
    expected_uniform_bytes = vector["uniform_bytes"]

    output = HashToCurve.expand_message_xmd(msg, DST, len_in_bytes)
    assert output == expected_uniform_bytes, f"Failed for msg: {vector['msg']}"


messages = st.binary()
lengths = st.integers(min_value=1, max_value=8160)  # 255 * 32
tags = st.binary(min_size=1, max_size=255)


@given(msg=messages, len_in_bytes=lengths, DST=tags)
def test_expand_message_xmd_properties(
    msg: bytes, len_in_bytes: int, DST: bytes
) -> None:
    output = HashToCurve.expand_message_xmd(msg, DST, len_in_bytes)
    assert len(output) == len_in_bytes


@given(msg=messages, len_in_bytes=lengths, DST=tags)
def test_expand_message_xmd_deterministic(
    msg: bytes, len_in_bytes: int, DST: bytes
) -> None:
    output1 = HashToCurve.expand_message_xmd(msg, DST, len_in_bytes)
    output2 = HashToCurve.expand_message_xmd(msg, DST, len_in_bytes)
    assert output1 == output2


@given(msg1=messages, msg2=messages, len_in_bytes=lengths, DST=tags)
def test_expand_message_xmd_different_messages(
    msg1: bytes, msg2: bytes, len_in_bytes: int, DST: bytes
) -> None:
    if msg1 == msg2:
        return
    output1 = HashToCurve.expand_message_xmd(msg1, DST, len_in_bytes)
    output2 = HashToCurve.expand_message_xmd(msg2, DST, len_in_bytes)
    assert output1 != output2
