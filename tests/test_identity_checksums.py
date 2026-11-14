"""
Gap 2 — validate_bank_account and validate_mrz against publicly documented
specimen numbers, through the MCP client API.

Reference numbers:
  IBAN  GB82 WEST 1234 5698 7654 32, DE89 3704 0044 0532 0130 00,
        ES91 2100 0418 4502 0005 1332 — standard ISO 13616 / bank examples
        (the ES one is the example in the tool's own input description).
  CLABE 032180000118359719 — the example published for the CLABE standard.
  CBU   2850590940090418135201 — widely published BCRA-format example.
  CVU   built in-test from the BCRA algorithm (PSP prefix 0000003, fictitious
        account 0000012345678): there is no public specimen CVU.
  MRZ   ICAO Doc 9303 specimens (Part 4 TD3 "ERIKSSON ANNA MARIA" passport,
        Part 5 TD1 ID card).

The reference implementations below follow the published specs and are
checked against the specimens, so an expected failure points at the tool.
"""
from __future__ import annotations

import pytest

from tests.mcp_client import call_tool

# ---------------------------------------------------------------------------
# Spec reference implementations (independent of src/)
# ---------------------------------------------------------------------------


def _bcra_check(digits: str, weights: list[int]) -> int:
    return (10 - sum(int(d) * w for d, w in zip(digits, weights)) % 10) % 10


def _cbu_is_valid(cbu: str) -> bool:
    """BCRA Comunicacion A 2795: block 1 weights 7139713, block 2 3971397139713."""
    return (
        int(cbu[7]) == _bcra_check(cbu[:7], [7, 1, 3, 9, 7, 1, 3])
        and int(cbu[21]) == _bcra_check(cbu[8:21], [3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3])
    )


def _make_cvu(psp7: str, account13: str) -> str:
    c1 = _bcra_check(psp7, [7, 1, 3, 9, 7, 1, 3])
    c2 = _bcra_check(account13, [3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3])
    return f"{psp7}{c1}{account13}{c2}"


def _change_digit(value: str, pos: int) -> str:
    """Replace the digit at ``pos`` (index into the string) with a different one."""
    assert value[pos].isdigit()
    return value[:pos] + str((int(value[pos]) + 1) % 10) + value[pos + 1:]


IBANS = [
    "GB82 WEST 1234 5698 7654 32",
    "DE89 3704 0044 0532 0130 00",
    "ES91 2100 0418 4502 0005 1332",
]
CLABE = "032180000118359719"
CBU = "2850590940090418135201"
CVU = _make_cvu("0000003", "0000012345678")


def test_reference_algorithms_accept_specimens():
    assert _cbu_is_valid(CBU)
    assert _cbu_is_valid(CVU)
    for iban in IBANS:
        clean = iban.replace(" ", "")
        n = "".join(str(int(c, 36)) for c in clean[4:] + clean[:4])
        assert int(n) % 97 == 1


def _bank(number: str, fmt: str = "auto"):
    return call_tool("validate_bank_account", account_number=number, format=fmt)


# ---------------------------------------------------------------------------
# IBAN
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("iban", IBANS)
def test_iban_valid(iban):
    res = _bank(iban, "iban")
    assert "CHECKSUM_VALID [IBAN]" in res.text, res.text
    assert "IBAN checksum valid (mod 97 = 1)" in res.text


@pytest.mark.parametrize("iban", IBANS)
@pytest.mark.parametrize("which", ["check_digits", "bban"])
def test_iban_one_digit_changed_fails(iban, which):
    clean = iban.replace(" ", "")
    pos = 3 if which == "check_digits" else len(clean) - 2
    res = _bank(_change_digit(clean, pos), "iban")
    assert "CHECKSUM_INVALID [IBAN]" in res.text, res.text
    assert "IBAN checksum FAILED" in res.text


def test_iban_wrong_length_fails():
    res = _bank("GB82WEST123456987654", "iban")
    assert "CHECKSUM_INVALID [IBAN]" in res.text
    assert "Invalid length for GB IBAN: expected 22, got 20" in res.text


@pytest.mark.xfail(strict=True, reason=(
    "BUG: with format='auto' _detect_format returns 'IBAN' (upper case) but the dispatcher "
    "only matches 'iban', so every auto-detected IBAN is reported FORMAT_UNRECOGNIZED."))
def test_iban_auto_detected():
    assert "CHECKSUM_VALID [IBAN]" in _bank(IBANS[0]).text


# ---------------------------------------------------------------------------
# CLABE
# ---------------------------------------------------------------------------


def test_clabe_valid():
    res = _bank(CLABE, "clabe")
    assert "CHECKSUM_VALID [CLABE]" in res.text, res.text
    assert "Bank: 032 | City: 180 | Account: 00011835971" in res.text


@pytest.mark.parametrize("pos", [0, 8, 17])
def test_clabe_one_digit_changed_fails(pos):
    res = _bank(_change_digit(CLABE, pos), "clabe")
    assert "CHECKSUM_INVALID [CLABE]" in res.text, res.text
    assert "CLABE check digit FAILED" in res.text


@pytest.mark.xfail(strict=True, reason=(
    "BUG: with format='auto' _detect_format returns 'CLABE' but the dispatcher only matches "
    "'clabe', so every auto-detected CLABE is reported FORMAT_UNRECOGNIZED."))
def test_clabe_auto_detected():
    assert "CHECKSUM_VALID [CLABE]" in _bank(CLABE).text


# ---------------------------------------------------------------------------
# CBU / CVU
# ---------------------------------------------------------------------------

_CBU_BUG = (
    "BUG: bank_tools._validate_cbu uses weights 3171713 for block 1 and only digits 15-21 for "
    "block 2; BCRA specifies 7139713 over digits 1-7 and 3971397139713 over digits 9-21, so "
    "genuine CBUs/CVUs are rejected.")


@pytest.mark.xfail(strict=True, reason=_CBU_BUG)
@pytest.mark.parametrize("fmt", ["cbu", "auto"])
def test_cbu_valid(fmt):
    assert "CHECKSUM_VALID [CBU]" in _bank(CBU, fmt).text


@pytest.mark.xfail(strict=True, reason=_CBU_BUG)
def test_cvu_valid():
    assert "CHECKSUM_VALID [CVU]" in _bank(CVU, "cvu").text


@pytest.mark.parametrize("pos", [2, 7, 12, 21])
def test_cbu_one_digit_changed_fails(pos):
    changed = _change_digit(CBU, pos)
    assert not _cbu_is_valid(changed)
    res = _bank(changed, "cbu")
    assert "CHECKSUM_INVALID [CBU]" in res.text, res.text


_CVU_FALSE_ACCEPT = pytest.mark.xfail(strict=True, reason=(
    "BUG (same root cause as the CBU weights): this altered CVU fails the BCRA check but happens "
    "to satisfy the tool's incorrect block-2 rule, so the tool reports it CHECKSUM_VALID."))


@pytest.mark.parametrize("pos", [
    5, 7,
    pytest.param(15, marks=_CVU_FALSE_ACCEPT),
    pytest.param(21, marks=_CVU_FALSE_ACCEPT),
])
def test_cvu_one_digit_changed_fails(pos):
    changed = _change_digit(CVU, pos)
    assert not _cbu_is_valid(changed)
    res = _bank(changed, "cvu")
    assert "CHECKSUM_INVALID [CVU]" in res.text, res.text


# ---------------------------------------------------------------------------
# Unrecognised formats
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["12345", "1234567890123456789012345", "ABCDEFG"])
def test_unrecognized_format(value):
    res = _bank(value)
    assert res.text.startswith("[FakeSpotter] FORMAT_UNRECOGNIZED"), res.text


def test_wrong_length_for_explicit_format():
    res = _bank("12345", "clabe")
    assert "CHECKSUM_INVALID [CLABE]" in res.text
    assert "must be exactly 18 digits" in res.text


# ---------------------------------------------------------------------------
# MRZ — ICAO Doc 9303 specimens
# ---------------------------------------------------------------------------

TD3 = [
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
]
TD1 = [
    "I<UTOD231458907<<<<<<<<<<<<<<<",
    "7408122F1204159UTO<<<<<<<<<<<6",
    "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
]


def _icao_check(field: str) -> int:
    values = {**{str(d): d for d in range(10)}, "<": 0,
              **{c: i + 10 for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}}
    return sum(values[c] * (7, 3, 1)[i % 3] for i, c in enumerate(field)) % 10


def test_icao_specimens_are_valid_by_spec():
    l2 = TD3[1]
    assert int(l2[9]) == _icao_check(l2[0:9])
    assert int(l2[19]) == _icao_check(l2[13:19])
    assert int(l2[27]) == _icao_check(l2[21:27])
    assert int(l2[42]) == _icao_check(l2[28:42])
    assert int(l2[43]) == _icao_check(l2[0:10] + l2[13:20] + l2[21:43])
    a, b, _ = TD1
    assert int(a[14]) == _icao_check(a[5:14])
    assert int(b[29]) == _icao_check(a[5:30] + b[0:7] + b[8:15] + b[18:29])


def _mrz(lines: list[str]):
    return call_tool("validate_mrz", mrz_lines=lines, report_mode="full")


def _mutate(lines: list[str], line: int, pos: int) -> list[str]:
    out = list(lines)
    out[line] = _change_digit(out[line], pos)
    return out


@pytest.mark.xfail(strict=True, reason=(
    "BUG: mrz_tools._parse_td3 reads the composite check digit from position 43 of line 2 "
    "(index 42, the personal-number check digit) and builds the composite string with the "
    "optional field twice and in the wrong order; the ICAO 9303 specimen passport fails."))
def test_td3_specimen_valid():
    res = _mrz(TD3)
    assert res.verdict == "MRZ_VALID", res.text


def test_td3_specimen_fields_parsed():
    res = call_tool("validate_mrz", mrz_lines=TD3)
    assert "[TD3_PASSPORT]" in res.text
    assert "ERIKSSON ANNA MARIA, UTO" in res.text


@pytest.mark.parametrize("pos,label", [
    (9, "Document number"),
    (19, "Date of birth"),
    (27, "Expiry date"),
])
def test_td3_changed_check_digit_fails(pos, label):
    res = _mrz(_mutate(TD3, 1, pos))
    assert res.verdict == "MRZ_CHECKSUM_FAILED", res.text
    assert f"{label}: ✗ checksum FAILED" in res.text


@pytest.mark.parametrize("pos", [42, 43], ids=["personal_number_check", "composite_check"])
def test_td3_changed_trailing_check_digit_fails(pos):
    res = _mrz(_mutate(TD3, 1, pos))
    assert res.verdict == "MRZ_CHECKSUM_FAILED", res.text


def test_td1_specimen_valid():
    res = _mrz(TD1)
    assert res.verdict == "MRZ_VALID", res.text
    assert "Composite check: ✓ checksum valid" in res.text
    quick = call_tool("validate_mrz", mrz_lines=TD1)
    assert "MRZ_VALID [TD1_ID_CARD]" in quick.text
    assert "4/4 checksums passed" in quick.text


@pytest.mark.parametrize("line,pos,label", [
    (0, 14, "Document number"),
    (1, 6, "Date of birth"),
    (1, 14, "Expiry date"),
    (1, 29, "Composite check"),
])
def test_td1_changed_check_digit_fails(line, pos, label):
    res = _mrz(_mutate(TD1, line, pos))
    assert res.verdict == "MRZ_CHECKSUM_FAILED", res.text
    assert f"{label}: ✗ checksum FAILED" in res.text


def test_td1_changed_data_digit_fails():
    # Date of birth 740812 -> 740813: the check digit no longer matches.
    res = _mrz(_mutate(TD1, 1, 5))
    assert res.verdict == "MRZ_CHECKSUM_FAILED"
    assert "Date of birth: ✗ checksum FAILED" in res.text


def test_mrz_format_invalid():
    res = _mrz([TD3[0][:40], TD3[1][:40]])
    assert res.verdict == "MRZ_FORMAT_INVALID", res.text


def test_mrz_requires_input():
    res = call_tool("validate_mrz")
    assert res.text == "[FakeSpotter Error] Provide either mrz_lines or image_url."
