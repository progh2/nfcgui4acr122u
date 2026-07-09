"""
하드웨어(ACR122U) 없이 검증 가능한 순수 로직 단위 테스트.

pyscard가 없어도 acr122u 모듈은 import되며(선택적 import), 여기서 테스트하는
NDEF 인코딩/디코딩과 바이트 정규화 함수는 하드웨어에 의존하지 않는다.
"""

import pathlib
import sys

import pytest

# 저장소 루트를 import 경로에 추가 (tests/ 하위에서 실행되어도 acr122u를 찾도록)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from acr122u import (  # noqa: E402
    ACR122U,
    ACR122UError,
    build_ndef_text_tlv,
    parse_ndef_text,
)


# ---------------------------------------------------------------------- #
# NDEF Text 레코드
# ---------------------------------------------------------------------- #
def test_ndef_text_roundtrip():
    tlv = build_ndef_text_tlv("Hello NFC", "en")
    assert parse_ndef_text(tlv) == "Hello NFC"


def test_ndef_text_unicode_roundtrip():
    tlv = build_ndef_text_tlv("안녕 NFC 🎉", "ko")
    assert parse_ndef_text(tlv) == "안녕 NFC 🎉"


def test_ndef_tlv_structure():
    tlv = build_ndef_text_tlv("Hi", "en")
    # TLV 배치: [03][record_len][D1][type_len=01][payload_len][54='T']...[FE]
    assert tlv[0] == 0x03           # NDEF 메시지 TLV 태그
    assert tlv[-1] == 0xFE          # 종료 TLV
    assert tlv[2] == 0xD1           # 레코드 헤더 (MB=ME=SR=1, TNF=well-known)
    assert tlv[3] == 0x01           # 타입 길이
    assert tlv[5:6] == b"T"         # 레코드 타입 'T'


def test_ndef_empty_text():
    tlv = build_ndef_text_tlv("", "en")
    assert parse_ndef_text(tlv) == ""


# ---------------------------------------------------------------------- #
# NDEF URI 레코드 파싱 (읽기 전용)
# ---------------------------------------------------------------------- #
def test_parse_uri_record_https():
    # URI 레코드: 접두어 0x04('https://') + 'example.com'
    payload = bytes([0x04]) + b"example.com"
    record = bytes([0xD1, 0x01, len(payload)]) + b"U" + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    assert parse_ndef_text(tlv) == "https://example.com"


def test_parse_uri_record_no_prefix():
    payload = bytes([0x00]) + b"custom://path"
    record = bytes([0xD1, 0x01, len(payload)]) + b"U" + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    assert parse_ndef_text(tlv) == "custom://path"


def test_parse_no_ndef_returns_none():
    # NULL TLV들 뒤 바로 종료 → NDEF 메시지 없음
    assert parse_ndef_text(bytes([0x00, 0x00, 0xFE])) is None


def test_parse_empty_returns_none():
    assert parse_ndef_text(b"") is None


# ---------------------------------------------------------------------- #
# 바이트/키 정규화
# ---------------------------------------------------------------------- #
def test_normalize_bytes_from_hexstring():
    assert ACR122U._normalize_bytes("FF00A1") == [0xFF, 0x00, 0xA1]


def test_normalize_bytes_ignores_spaces_and_colons():
    assert ACR122U._normalize_bytes("FF 00 A1") == [0xFF, 0x00, 0xA1]
    assert ACR122U._normalize_bytes("FF:00:A1") == [0xFF, 0x00, 0xA1]


def test_normalize_bytes_from_list():
    assert ACR122U._normalize_bytes([255, 0, 161]) == [0xFF, 0x00, 0xA1]
    # 0xFF 마스킹 확인
    assert ACR122U._normalize_bytes([0x1FF]) == [0xFF]


def test_normalize_bytes_odd_length_raises():
    with pytest.raises(ACR122UError):
        ACR122U._normalize_bytes("FFA")


def test_normalize_bytes_invalid_hex_raises():
    with pytest.raises(ACR122UError):
        ACR122U._normalize_bytes("GG")


def test_normalize_key_valid():
    assert ACR122U._normalize_key("FFFFFFFFFFFF") == [0xFF] * 6


def test_normalize_key_wrong_length_raises():
    with pytest.raises(ACR122UError):
        ACR122U._normalize_key("FFFF")
    with pytest.raises(ACR122UError):
        ACR122U._normalize_key([0x01] * 7)
