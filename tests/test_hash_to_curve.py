import pytest
from hypothesis import given, strategies as st
from src.ecc import HashToCurve, P, Z, Point

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


@given(msg=messages, len_in_bytes=st.integers(min_value=8161), DST=tags)
def test_expand_message_xmd_large_len_in_bytes(
    msg: bytes, len_in_bytes: int, DST: bytes
) -> None:
    with pytest.raises(
        ValueError,
        match="Ell is too large",
    ):
        HashToCurve.expand_message_xmd(msg, DST, len_in_bytes)


def test_sqrt_ratio_3mod4_known_values() -> None:
    # Known quadratic residue
    u = 4  # 4 is a perfect square modulo p
    v = 1
    isQR, y = HashToCurve.sqrt_ratio_3mod4(u, v)
    assert isQR is True, "Expected isQR == True for u=4, v=1"
    assert y == 2, "Expected y == 2 for sqrt(4)"

    # Known non-quadratic residue
    u = 3  # 3 is not a perfect square modulo p
    v = 1
    isQR, y = HashToCurve.sqrt_ratio_3mod4(u, v)
    assert isQR is False, "Expected isQR == False for u=3, v=1"
    # Verify that y^2 == Z * u mod p
    lhs = (y * y) % P
    rhs = (Z * u) % P
    assert lhs == rhs, "Expected y^2 == Z * u mod p"


@given(
    u=st.integers(min_value=0, max_value=P - 1),
    v=st.integers(min_value=1, max_value=P - 1),
)
def test_sqrt_ratio_3mod4_properties(u: int, v: int) -> None:
    isQR, y = HashToCurve.sqrt_ratio_3mod4(u, v)
    lhs = (y * y * v) % P
    if isQR:
        rhs = u % P
    else:
        rhs = (Z * u) % P
    assert lhs == rhs, (
        f"Property failed for u={u}, v={v}, isQR={isQR}\n"
        f"Computed lhs={lhs}, rhs={rhs}"
    )


@given(v=st.integers(min_value=1, max_value=P - 1))
def test_sqrt_ratio_3mod4_u_zero(v: int) -> None:
    u = 0
    isQR, y = HashToCurve.sqrt_ratio_3mod4(u, v)
    assert isQR is True, f"Expected isQR == True when u = 0, got {isQR}"
    assert y == 0, f"Expected y == 0 when u = 0, got {y}"


@given(
    u=st.integers(min_value=0, max_value=P - 1),
    v=st.integers(min_value=1, max_value=P - 1),
)
def test_sqrt_ratio_3mod4_determinism(u: int, v: int) -> None:
    isQR1, y1 = HashToCurve.sqrt_ratio_3mod4(u, v)
    isQR2, y2 = HashToCurve.sqrt_ratio_3mod4(u, v)
    assert isQR1 == isQR2, "isQR values differ on repeated calls"
    assert y1 == y2, "y values differ on repeated calls"


test_vectors2 = [
    {
        "msg": "",
        "u": [
            "6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3",
            "1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16",
        ],
        "Q0": {
            "x": "74519ef88b32b425a095e4ebcc84d81b64e9e2c2675340a720bb1a1857b9"
            "9f1e",
            "y": "c174fa322ab7c192e11748beed45b508e9fdb1ce046dee9c2cd3a2a86b41"
            "0936",
        },
        "Q1": {
            "x": "44548adb1b399263ded3510554d28b4bead34b8cf9a37b4bd0bd2ba4db87"
            "ae63",
            "y": "96eb8e2faf05e368efe5957c6167001760233e6dd2487516b46ae725c4cc"
            "e0c6",
        },
        "P": {
            "x": "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb"
            "1346",
            "y": "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e5"
            "1067",
        },
    },
    {
        "msg": "abc",
        "u": [
            "128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61",
            "5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00",
        ],
        "Q0": {
            "x": "07dd9432d426845fb19857d1b3a91722436604ccbbbadad8523b8fc38a53"
            "22d7",
            "y": "604588ef5138cffe3277bbd590b8550bcbe0e523bbaf1bed4014a467122e"
            "b33f",
        },
        "Q1": {
            "x": "e9ef9794d15d4e77dde751e06c182782046b8dac05f8491eb88764fc6532"
            "1f78",
            "y": "cb07ce53670d5314bf236ee2c871455c562dd76314aa41f012919fe8e7f7"
            "17b3",
        },
        "P": {
            "x": "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb"
            "2c4b",
            "y": "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c83"
            "71f6",
        },
    },
    {
        "msg": "abcdef0123456789",
        "u": [
            "ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9",
            "7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18",
        ],
        "Q0": {
            "x": "576d43ab0260275adf11af990d130a5752704f7947862876172080886254"
            "4b5d",
            "y": "643c4a7fb68ae6cff55edd66b809087434bbaff0c07f3f9ec4d49bb3c166"
            "23c3",
        },
        "Q1": {
            "x": "f89d6d261a5e00fe5cf45e827b507643e67c2a947a20fd9ad71039f8b0e2"
            "9ff8",
            "y": "b33855e0cc34a9176ead91c6c3acb1aacb1ce936d563bc1cee1dcffc806c"
            "af57",
        },
        "P": {
            "x": "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b"
            "0e3a",
            "y": "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758"
            "d828",
        },
    },
    {
        "msg": "q128_" + "q" * 128,
        "u": [
            "eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5",
            "dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d",
        ],
        "Q0": {
            "x": "9c91513ccfe9520c9c645588dff5f9b4e92eaf6ad4ab6f1cd720d192eb58"
            "247a",
            "y": "c7371dcd0134412f221e386f8d68f49e7fa36f9037676e163d4a063fbf8a"
            "1fb8",
        },
        "Q1": {
            "x": "10fee3284d7be6bd5912503b972fc52bf4761f47141a0015f1c6ae36848d"
            "869b",
            "y": "0b163d9b4bf21887364332be3eff3c870fa053cf508732900fc69a6eb0e1"
            "b672",
        },
        "P": {
            "x": "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e418"
            "90e9",
            "y": "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685"
            "d873",
        },
    },
    {
        "msg": "a512_" + "a" * 512,
        "u": [
            "8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f",
            "68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938",
        ],
        "Q0": {
            "x": "b32b0ab55977b936f1e93fdc68cec775e13245e161dbfe556bbb1f72799b"
            "4181",
            "y": "2f5317098360b722f132d7156a94822641b615c91f8663be69169870a12a"
            "f9e8",
        },
        "Q1": {
            "x": "148f98780f19388b9fa93e7dc567b5a673e5fca7079cd9cdafd71982ec4c"
            "5e12",
            "y": "3989645d83a433bc0c001f3dac29af861f33a6fd1e04f4b36873f5bff497"
            "298a",
        },
        "P": {
            "x": "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7"
            "c998",
            "y": "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee582"
            "3aa6",
        },
    },
]


@pytest.mark.parametrize("vector2", test_vectors2)
def test_hash_to_curve(vector2: dict) -> None:
    msg = vector2["msg"].encode("utf-8")
    expected_u = vector2["u"]
    expected_Q0 = vector2["Q0"]
    expected_Q1 = vector2["Q1"]
    expected_P = vector2["P"]
    DST = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"

    u = HashToCurve.hash_to_field(msg, 2, DST)
    assert u[0] == int(expected_u[0], 16)

    Q0_prime = HashToCurve.map_to_curve_simple_swu(u[0])
    Q0 = HashToCurve.iso_map(*Q0_prime)
    assert Q0[0] == int(expected_Q0["x"], 16)
    assert Q0[1] == int(expected_Q0["y"], 16)

    Q1_prime = HashToCurve.map_to_curve_simple_swu(u[1])
    Q1 = HashToCurve.iso_map(*Q1_prime)
    assert Q1[0] == int(expected_Q1["x"], 16)
    assert Q1[1] == int(expected_Q1["y"], 16)

    expected_R = Point(int(expected_P["x"], 16), int(expected_P["y"], 16))
    R = HashToCurve.hash_to_curve(msg, DST)
    assert R == expected_R
