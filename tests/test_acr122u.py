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

import acr122u  # noqa: E402
from acr122u import (  # noqa: E402
    ACR122U,
    ACR122UError,
    build_ndef_text_tlv,
    build_ndef_uri_tlv,
    parse_ndef_text,
    build_encrypted_container,
    parse_encrypted_container,
    encrypt_bytes,
    decrypt_bytes,
    build_wifi_wsc,
    build_wifi_wsc_ndef_tlv,
    parse_wifi_wsc,
    parse_wifi_from_tag,
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


def test_uri_roundtrip():
    tlv = build_ndef_uri_tlv("https://example.com/path")
    assert parse_ndef_text(tlv) == "https://example.com/path"


def test_uri_prefix_compression_https():
    # 'https://' → 접두어 코드 0x04, 본문에는 스킴이 빠져 있어야 함
    tlv = build_ndef_uri_tlv("https://school.ac.kr")
    assert tlv[0] == 0x03 and tlv[-1] == 0xFE
    assert b"https://" not in tlv        # 접두어로 압축됨
    assert b"school.ac.kr" in tlv


def test_uri_prefix_compression_www():
    tlv = build_ndef_uri_tlv("http://www.example.com")
    # 페이로드 첫 바이트(URI 코드) == 0x01 (http://www.)
    # TLV: [03][len][D1][01][plen]['U'][code]...
    assert tlv[6] == 0x01


def test_uri_tel_scheme():
    tlv = build_ndef_uri_tlv("tel:+82212345678")
    assert parse_ndef_text(tlv) == "tel:+82212345678"


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


# ---------------------------------------------------------------------- #
# 비밀번호 기반 AES 암호화
# ---------------------------------------------------------------------- #
crypto = pytest.mark.skipif(
    not acr122u.CRYPTO_AVAILABLE, reason="cryptography 미설치"
)


@crypto
def test_encrypt_decrypt_roundtrip():
    blob = encrypt_bytes("secret message", "pw1234")
    assert decrypt_bytes(blob, "pw1234") == "secret message"


@crypto
def test_encrypt_unicode_roundtrip():
    blob = encrypt_bytes("비밀 메시지 🔒", "한글암호")
    assert decrypt_bytes(blob, "한글암호") == "비밀 메시지 🔒"


@crypto
def test_decrypt_wrong_password_raises():
    blob = encrypt_bytes("top secret", "correct")
    with pytest.raises(ACR122UError):
        decrypt_bytes(blob, "wrong")


@crypto
def test_encrypt_is_nondeterministic():
    # 매번 다른 salt/nonce → 같은 평문·비밀번호라도 암호문이 달라야 함
    a = encrypt_bytes("same", "pw")
    b = encrypt_bytes("same", "pw")
    assert a != b


@crypto
def test_container_roundtrip():
    container = build_encrypted_container("payload here", "mypw")
    assert container[:4] == b"ENC1"
    assert parse_encrypted_container(container, "mypw") == "payload here"


@crypto
def test_container_with_trailing_padding():
    # 태그 읽기는 4바이트 배수로 패딩된 데이터를 돌려줄 수 있음 → 파싱이 견뎌야 함
    container = build_encrypted_container("hello", "pw")
    padded = container + bytes(3)
    assert parse_encrypted_container(padded, "pw") == "hello"


@crypto
def test_container_wrong_password_raises():
    container = build_encrypted_container("data", "right")
    with pytest.raises(ACR122UError):
        parse_encrypted_container(container, "nope")


def test_parse_container_no_magic_returns_none():
    assert parse_encrypted_container(bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), "pw") is None


# ---------------------------------------------------------------------- #
# WiFi WSC (WPS) 태그
# ---------------------------------------------------------------------- #
def test_wifi_wsc_roundtrip():
    payload = build_wifi_wsc("SchoolWiFi", "s3cret!!", "WPA2-PSK")
    info = parse_wifi_wsc(payload)
    assert info["ssid"] == "SchoolWiFi"
    assert info["password"] == "s3cret!!"
    assert info["auth"] == "WPA2-PSK"
    assert info["enc"] == "AES"


def test_wifi_ndef_structure():
    tlv = build_wifi_wsc_ndef_tlv("Net", "pass1234", "WPA2-PSK")
    assert tlv[0] == 0x03           # NDEF 메시지 TLV
    assert tlv[-1] == 0xFE          # 종료 TLV
    assert b"application/vnd.wfa.wsc" in tlv   # media-type 레코드
    assert tlv[2] == 0xD2           # 레코드 헤더 (MB=ME=SR=1, TNF=media)


def test_wifi_from_tag_roundtrip():
    tlv = build_wifi_wsc_ndef_tlv("교실WiFi", "비번1234abcd", "WPA/WPA2-PSK")
    info = parse_wifi_from_tag(tlv)
    assert info["ssid"] == "교실WiFi"
    assert info["password"] == "비번1234abcd"
    assert info["auth"] == "WPA/WPA2-PSK"


def test_wifi_open_network_has_no_password():
    payload = build_wifi_wsc("FreeWiFi", "", "OPEN")
    info = parse_wifi_wsc(payload)
    assert info["ssid"] == "FreeWiFi"
    assert info["auth"] == "OPEN"
    assert info["enc"] == "NONE"
    assert "password" not in info


def test_wifi_invalid_auth_raises():
    with pytest.raises(ACR122UError):
        build_wifi_wsc("X", "y", "WPA3-SAE")


def test_wifi_from_tag_no_wifi_returns_none():
    # 일반 텍스트 NDEF에는 WiFi 레코드가 없음
    text_tlv = build_ndef_text_tlv("hello", "en")
    assert parse_wifi_from_tag(text_tlv) is None
