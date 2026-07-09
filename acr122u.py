"""
ACR122U NFC 리더/라이터 제어 모듈.

ACR122U는 PC/SC 규격 장치이므로 pyscard 라이브러리를 통해 APDU 명령을 주고받습니다.
이 모듈은 GUI(main.py)에서 사용하는 저수준 장치 래퍼를 제공합니다.

주요 기능
  - 리더 검색 / 카드 연결
  - UID 읽기, ATR·펌웨어·카드 종류 조회
  - MIFARE Classic 인증 후 블록 읽기/쓰기
  - MIFARE Ultralight / NTAG 페이지 읽기/쓰기
  - NDEF 텍스트 레코드 읽기/쓰기 (NTAG 등)
  - 부저 / LED 제어
"""

import os

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes  # noqa: F401  (toBytes는 외부에서 활용)
    from smartcard.Exceptions import NoCardException, CardConnectionException
    PYSCARD_AVAILABLE = True
except ImportError:
    # pyscard 미설치 환경(순수 로직 단위 테스트/CI 등)에서도 import가 가능하도록
    # 대체 정의를 둔다. 실제 하드웨어 접근 시에만 오류를 발생시킨다.
    PYSCARD_AVAILABLE = False

    class NoCardException(Exception):
        pass

    class CardConnectionException(Exception):
        pass

    def readers():
        raise ACR122UError(
            "pyscard가 설치되어 있지 않습니다. 'pip install pyscard'로 설치하세요."
        )

    def toHexString(data, *args, **kwargs):
        return " ".join(f"{b:02X}" for b in data)

    def toBytes(s):
        cleaned = s.replace(" ", "")
        return [int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2)]


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class ACR122UError(Exception):
    """장치/카드 명령 처리 중 발생하는 오류."""


# ATR 안의 카드 이름 바이트 → 사람이 읽는 이름
CARD_NAMES = {
    (0x00, 0x01): "MIFARE Classic 1K",
    (0x00, 0x02): "MIFARE Classic 4K",
    (0x00, 0x03): "MIFARE Ultralight",
    (0x00, 0x26): "MIFARE Mini",
    (0x00, 0x3A): "MIFARE Ultralight C",
    (0x00, 0x36): "MIFARE Plus 2K",
    (0x00, 0x37): "MIFARE Plus 4K",
    (0xF0, 0x04): "Topaz / Jewel",
    (0xF0, 0x11): "FeliCa 212K",
    (0xF0, 0x12): "FeliCa 424K",
    (0xFF, 0x88): "MIFARE DESFire",
}


class ACR122U:
    """ACR122U 단일 장치를 다루는 래퍼."""

    def __init__(self, reader_name=None):
        self._reader = None
        self._conn = None
        if reader_name is not None:
            self.select_reader(reader_name)

    # ------------------------------------------------------------------ #
    # 리더 / 연결 관리
    # ------------------------------------------------------------------ #
    @staticmethod
    def list_readers():
        """연결된 PC/SC 리더 이름 목록을 반환."""
        return [str(r) for r in readers()]

    def select_reader(self, reader_name=None):
        """
        사용할 리더를 선택.
        reader_name이 None이면 이름에 'ACR122'가 포함된 리더를,
        없으면 첫 번째 리더를 사용한다.
        """
        available = readers()
        if not available:
            raise ACR122UError(
                "PC/SC 리더를 찾을 수 없습니다. 장치 연결과 드라이버를 확인하세요."
            )
        if reader_name:
            for r in available:
                if reader_name in str(r):
                    self._reader = r
                    return str(r)
            raise ACR122UError(f"리더를 찾을 수 없습니다: {reader_name}")
        for r in available:
            if "ACR122" in str(r):
                self._reader = r
                return str(r)
        self._reader = available[0]
        return str(available[0])

    @property
    def reader_name(self):
        return str(self._reader) if self._reader else None

    def connect(self):
        """현재 리더에 놓인 카드에 연결한다. 카드가 없으면 예외 발생."""
        if self._reader is None:
            self.select_reader()
        conn = self._reader.createConnection()
        conn.connect()  # 카드가 없으면 NoCardException
        self._conn = conn
        return conn

    def disconnect(self):
        """카드 연결을 해제한다."""
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def is_connected(self):
        return self._conn is not None

    # ------------------------------------------------------------------ #
    # 저수준 APDU 송수신
    # ------------------------------------------------------------------ #
    def transmit(self, apdu):
        """
        APDU(정수 리스트)를 전송하고 (data, sw1, sw2)를 반환한다.
        """
        if self._conn is None:
            raise ACR122UError("카드에 연결되어 있지 않습니다.")
        try:
            data, sw1, sw2 = self._conn.transmit(list(apdu))
        except (NoCardException, CardConnectionException) as e:
            raise ACR122UError(f"통신 오류: {e}")
        return data, sw1, sw2

    @staticmethod
    def _ok(sw1, sw2):
        return (sw1, sw2) == (0x90, 0x00)

    def _require_ok(self, data, sw1, sw2, msg="명령 실패"):
        if not self._ok(sw1, sw2):
            raise ACR122UError(f"{msg} (SW={sw1:02X}{sw2:02X})")
        return data

    # ------------------------------------------------------------------ #
    # 카드 정보 조회
    # ------------------------------------------------------------------ #
    def get_uid(self):
        """카드 UID를 16진수 문자열(공백 없음)로 반환."""
        data, sw1, sw2 = self.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        self._require_ok(data, sw1, sw2, "UID 읽기 실패")
        return "".join(f"{b:02X}" for b in data)

    def get_atr(self):
        """ATR을 16진수 문자열로 반환."""
        if self._conn is None:
            raise ACR122UError("카드에 연결되어 있지 않습니다.")
        return toHexString(self._conn.getATR())

    def identify_card(self):
        """ATR로부터 카드 종류를 추정."""
        if self._conn is None:
            raise ACR122UError("카드에 연결되어 있지 않습니다.")
        atr = self._conn.getATR()
        # 저장형 카드 표준 ATR: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 SS C0 C1 ...
        if len(atr) >= 15 and atr[0] == 0x3B and atr[13] is not None:
            name = (atr[13], atr[14])
            return CARD_NAMES.get(name, f"알 수 없음 (코드 {atr[13]:02X}{atr[14]:02X})")
        return "알 수 없음 (일반 스마트카드일 수 있음)"

    def get_firmware_version(self):
        """리더 펌웨어 버전 문자열을 반환 (예: 'ACR122U210')."""
        data, sw1, sw2 = self.transmit([0xFF, 0x00, 0x48, 0x00, 0x00])
        # 이 명령은 응답 전체(데이터 + SW1 + SW2)가 ASCII 버전 문자열이다.
        raw = list(data) + [sw1, sw2]
        return "".join(chr(b) for b in raw if 32 <= b < 127)

    # ------------------------------------------------------------------ #
    # MIFARE Classic: 키 로드 / 인증 / 블록 R·W
    # ------------------------------------------------------------------ #
    def load_key(self, key, key_slot=0x00):
        """
        인증 키(6바이트)를 리더의 휘발성 슬롯에 적재.
        key: 정수 6개 리스트 또는 12자리 16진수 문자열.
        """
        key = self._normalize_key(key)
        apdu = [0xFF, 0x82, 0x00, key_slot, 0x06] + key
        self._require_ok(*self.transmit(apdu), msg="키 적재 실패")

    def authenticate(self, block, key_type="A", key_slot=0x00):
        """
        MIFARE Classic 블록 인증. load_key로 키를 먼저 적재해야 한다.
        key_type: 'A' 또는 'B'.
        """
        kt = 0x60 if str(key_type).upper() == "A" else 0x61
        apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, kt, key_slot]
        self._require_ok(*self.transmit(apdu), msg=f"블록 {block} 인증 실패")

    def read_block(self, block, length=16):
        """블록(또는 Ultralight 페이지 시작)에서 length 바이트를 읽어 정수 리스트로 반환."""
        data, sw1, sw2 = self.transmit([0xFF, 0xB0, 0x00, block, length])
        self._require_ok(data, sw1, sw2, f"블록 {block} 읽기 실패")
        return list(data)

    def write_block(self, block, data):
        """
        블록/페이지에 data를 기록.
        MIFARE Classic은 16바이트, Ultralight/NTAG는 4바이트 단위.
        data: 정수 리스트 또는 16진수 문자열.
        """
        data = self._normalize_bytes(data)
        apdu = [0xFF, 0xD6, 0x00, block, len(data)] + data
        self._require_ok(*self.transmit(apdu), msg=f"블록 {block} 쓰기 실패")

    def read_classic_block(self, block, key, key_type="A", key_slot=0x00):
        """MIFARE Classic 편의 함수: 키 적재 → 인증 → 읽기."""
        self.load_key(key, key_slot)
        self.authenticate(block, key_type, key_slot)
        return self.read_block(block, 16)

    def write_classic_block(self, block, data, key, key_type="A", key_slot=0x00):
        """MIFARE Classic 편의 함수: 키 적재 → 인증 → 쓰기."""
        self.load_key(key, key_slot)
        self.authenticate(block, key_type, key_slot)
        self.write_block(block, data)

    # ------------------------------------------------------------------ #
    # NDEF 텍스트 (NTAG / Ultralight)
    # ------------------------------------------------------------------ #
    def write_ndef_text(self, text, lang="en", start_page=4):
        """텍스트를 NDEF Text 레코드로 만들어 NTAG/Ultralight에 기록."""
        tlv = build_ndef_text_tlv(text, lang)
        # 4바이트 배수로 패딩
        if len(tlv) % 4:
            tlv += bytes(4 - (len(tlv) % 4))
        page = start_page
        for i in range(0, len(tlv), 4):
            self.write_block(page, list(tlv[i:i + 4]))
            page += 1
        return page - start_page  # 기록한 페이지 수

    def read_ndef_text(self, start_page=4, max_pages=40):
        """NTAG/Ultralight에서 NDEF Text 레코드를 읽어 문자열로 반환 (없으면 None)."""
        buf = []
        page = start_page
        while page < start_page + max_pages:
            try:
                buf += self.read_block(page, 16)  # 한 번에 4페이지(16B)
            except ACR122UError:
                break
            page += 4
        return parse_ndef_text(bytes(buf))

    # ------------------------------------------------------------------ #
    # 비밀번호 기반 AES 암호화 데이터 (NTAG / Ultralight)
    # ------------------------------------------------------------------ #
    def write_encrypted(self, text, password, start_page=4):
        """
        text를 비밀번호로 AES-256-GCM 암호화하여 NTAG/Ultralight에 기록.
        기록한 페이지 수를 반환한다.
        """
        container = build_encrypted_container(text, password)
        if len(container) % 4:
            container += bytes(4 - (len(container) % 4))
        page = start_page
        for i in range(0, len(container), 4):
            self.write_block(page, list(container[i:i + 4]))
            page += 1
        return page - start_page

    def read_encrypted(self, password, start_page=4, max_pages=120):
        """
        NTAG/Ultralight에서 암호화 컨테이너를 읽어 비밀번호로 복호화한 문자열을 반환.
        컨테이너가 없으면 None, 비밀번호 오류/변조 시 ACR122UError.

        헤더(매직+길이)를 먼저 확보해 필요한 만큼만 페이지 단위로 읽는다.
        (4페이지 묶음으로 읽으면 끝부분 조각을 잃을 수 있어 페이지 단위로 처리)
        """
        buf = bytearray()
        needed = None
        for page in range(start_page, start_page + max_pages):
            try:
                buf += bytes(self.read_block(page, 4))
            except ACR122UError:
                break
            if needed is None and len(buf) >= 6:
                if bytes(buf[:4]) != ENC_MAGIC:
                    return None  # 암호화 컨테이너가 아님
                needed = 6 + int.from_bytes(bytes(buf[4:6]), "big")
            if needed is not None and len(buf) >= needed:
                break
        return parse_encrypted_container(bytes(buf), password)

    # ------------------------------------------------------------------ #
    # WiFi 접속정보 (WPS/WSC NDEF) — NTAG / Ultralight
    # ------------------------------------------------------------------ #
    def write_wifi(self, ssid, password, auth="WPA2-PSK", enc=None, start_page=4):
        """
        WiFi 접속정보를 WSC NDEF 레코드로 NTAG/Ultralight에 기록.
        enc가 None이면 auth에 맞춰 자동 선택. 기록한 페이지 수를 반환.
        """
        tlv = build_wifi_wsc_ndef_tlv(ssid, password, auth, enc)
        if len(tlv) % 4:
            tlv += bytes(4 - (len(tlv) % 4))
        page = start_page
        for i in range(0, len(tlv), 4):
            self.write_block(page, list(tlv[i:i + 4]))
            page += 1
        return page - start_page

    def read_wifi(self, start_page=4, max_pages=48):
        """NTAG/Ultralight에서 WiFi WSC 레코드를 읽어 dict로 반환 (없으면 None)."""
        buf = bytearray()
        for page in range(start_page, start_page + max_pages):
            try:
                buf += bytes(self.read_block(page, 4))
            except ACR122UError:
                break
        return parse_wifi_from_tag(bytes(buf))

    # ------------------------------------------------------------------ #
    # 부저 / LED
    # ------------------------------------------------------------------ #
    def led_buzzer(self, led_state, t1=0x02, t2=0x00, reps=0x01, buzzer=0x01):
        """
        LED 및 부저 제어 (FF 00 40 ...).
        led_state: LED 상태/블링크 제어 바이트
        t1, t2   : 블링크 지속 시간 (x100ms)
        reps     : 반복 횟수
        buzzer   : 0=무음, 1=T1 구간 소리, 2=T2 구간, 3=T1+T2
        """
        apdu = [0xFF, 0x00, 0x40, led_state, 0x04, t1, t2, reps, buzzer]
        # 이 명령의 SW는 현재 LED 상태를 담아 90 00이 아닐 수 있으므로 예외로 보지 않음
        return self.transmit(apdu)

    def beep(self, duration=0x02, reps=0x01):
        """간단한 '삑' 소리 (녹색 LED 깜빡임 동반)."""
        self.led_buzzer(0x50, t1=duration, t2=0x00, reps=reps, buzzer=0x01)

    def set_buzzer_on_detect(self, enable=True):
        """카드 인식 시 자동 부저음 켜기/끄기 (FF 00 52 ...)."""
        state = 0xFF if enable else 0x00
        self._require_ok(
            *self.transmit([0xFF, 0x00, 0x52, state, 0x00]),
            msg="부저 설정 실패",
        )

    # ------------------------------------------------------------------ #
    # 내부 유틸
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_bytes(data):
        """정수 리스트 또는 16진수 문자열을 정수 리스트로 변환."""
        if isinstance(data, str):
            cleaned = data.replace(" ", "").replace(":", "")
            if len(cleaned) % 2 != 0:
                raise ACR122UError("16진수 문자열의 길이가 올바르지 않습니다.")
            try:
                return [int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2)]
            except ValueError:
                raise ACR122UError("올바른 16진수 문자열이 아닙니다.")
        return [int(b) & 0xFF for b in data]

    @classmethod
    def _normalize_key(cls, key):
        k = cls._normalize_bytes(key)
        if len(k) != 6:
            raise ACR122UError("인증 키는 6바이트(16진수 12자리)여야 합니다.")
        return k


# ---------------------------------------------------------------------- #
# NDEF 헬퍼 (모듈 함수)
# ---------------------------------------------------------------------- #
def build_ndef_text_tlv(text, lang="en"):
    """NDEF Text 레코드를 TLV로 감싸 bytes로 반환."""
    lang_bytes = lang.encode("ascii")
    payload = bytes([len(lang_bytes)]) + lang_bytes + text.encode("utf-8")
    # 레코드 헤더: MB=1, ME=1, SR=1, TNF=001(well-known) → 0xD1
    record = bytes([0xD1, 0x01, len(payload)]) + b"T" + payload
    # TLV: 0x03(NDEF) <len> <record> 0xFE(종료)
    return bytes([0x03, len(record)]) + record + bytes([0xFE])


def parse_ndef_text(data):
    """바이트열에서 NDEF Text 레코드를 찾아 텍스트를 반환 (없으면 None)."""
    i = 0
    n = len(data)
    while i < n:
        t = data[i]
        if t == 0x00:  # NULL TLV
            i += 1
            continue
        if t == 0xFE:  # 종료 TLV
            break
        if i + 1 >= n:
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if t == 0x03:  # NDEF 메시지 TLV
            return _parse_ndef_record(value)
        i += 2 + length
    return None


def _parse_ndef_record(rec):
    """단일 짧은(SR) NDEF 레코드에서 Text 페이로드를 추출."""
    if len(rec) < 3:
        return None
    type_len = rec[1]
    payload_len = rec[2]
    idx = 3
    rec_type = rec[idx:idx + type_len]
    idx += type_len
    payload = rec[idx:idx + payload_len]
    if rec_type == b"T" and payload:
        status = payload[0]
        lang_len = status & 0x3F
        return payload[1 + lang_len:].decode("utf-8", errors="replace")
    if rec_type == b"U" and payload:
        # URI 레코드(선택): 접두어 코드 + 나머지 문자열
        prefixes = [
            "", "http://www.", "https://www.", "http://", "https://",
            "tel:", "mailto:",
        ]
        code = payload[0]
        prefix = prefixes[code] if code < len(prefixes) else ""
        return prefix + payload[1:].decode("utf-8", errors="replace")
    return None


# ---------------------------------------------------------------------- #
# 비밀번호 기반 AES 암호화 헬퍼 (모듈 함수)
# ---------------------------------------------------------------------- #
ENC_MAGIC = b"ENC1"          # 암호화 컨테이너 식별자
_KDF_ITERATIONS = 200_000    # PBKDF2 반복 횟수
_SALT_LEN = 16
_NONCE_LEN = 12


def _derive_key(password, salt):
    """PBKDF2-HMAC-SHA256으로 32바이트(AES-256) 키를 유도."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(text, password):
    """
    문자열을 비밀번호로 AES-256-GCM 암호화.
    반환 형식: salt(16) + nonce(12) + ciphertext+tag(bytes)
    """
    if not CRYPTO_AVAILABLE:
        raise ACR122UError(
            "cryptography 라이브러리가 필요합니다. 'pip install cryptography'로 설치하세요."
        )
    if not password:
        raise ACR122UError("비밀번호가 비어 있습니다.")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    return salt + nonce + ciphertext


def decrypt_bytes(blob, password):
    """encrypt_bytes 형식의 바이트열을 복호화하여 문자열 반환."""
    if not CRYPTO_AVAILABLE:
        raise ACR122UError(
            "cryptography 라이브러리가 필요합니다. 'pip install cryptography'로 설치하세요."
        )
    if len(blob) < _SALT_LEN + _NONCE_LEN + 16:
        raise ACR122UError("암호화 데이터가 손상되었거나 너무 짧습니다.")
    salt = blob[:_SALT_LEN]
    nonce = blob[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ciphertext = blob[_SALT_LEN + _NONCE_LEN:]
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ACR122UError("복호화 실패: 비밀번호가 틀렸거나 데이터가 손상되었습니다.")
    return plaintext.decode("utf-8")


def build_encrypted_container(text, password):
    """암호문에 매직/길이 헤더를 붙여 태그 저장용 컨테이너 bytes를 생성."""
    payload = encrypt_bytes(text, password)
    if len(payload) > 0xFFFF:
        raise ACR122UError("데이터가 너무 큽니다(최대 65535바이트).")
    return ENC_MAGIC + len(payload).to_bytes(2, "big") + payload


def parse_encrypted_container(data, password):
    """
    태그에서 읽은 바이트열에서 암호화 컨테이너를 찾아 복호화.
    유효한 컨테이너가 없으면 None을 반환한다.
    """
    if len(data) < 6 or bytes(data[:4]) != ENC_MAGIC:
        return None
    length = int.from_bytes(bytes(data[4:6]), "big")
    payload = bytes(data[6:6 + length])
    if len(payload) < length:
        raise ACR122UError("암호화 데이터가 불완전합니다(길이 부족).")
    return decrypt_bytes(payload, password)


# ---------------------------------------------------------------------- #
# WiFi 접속정보 (WPS / WSC NDEF) 헬퍼
# ---------------------------------------------------------------------- #
# WSC 속성 ID
_WSC_CREDENTIAL = 0x100E
_WSC_NETWORK_INDEX = 0x1026
_WSC_SSID = 0x1045
_WSC_AUTH_TYPE = 0x1003
_WSC_ENC_TYPE = 0x100F
_WSC_NETWORK_KEY = 0x1027
_WSC_MAC_ADDRESS = 0x1020

WIFI_AUTH = {
    "OPEN": 0x0001,
    "WPA-PSK": 0x0002,
    "WPA2-PSK": 0x0020,
    "WPA/WPA2-PSK": 0x0022,
}
WIFI_ENC = {
    "NONE": 0x0001,
    "WEP": 0x0002,
    "TKIP": 0x0004,
    "AES": 0x0008,
    "AES/TKIP": 0x000C,
}
# auth → 기본 encryption
_DEFAULT_ENC = {
    "OPEN": "NONE",
    "WPA-PSK": "TKIP",
    "WPA2-PSK": "AES",
    "WPA/WPA2-PSK": "AES",
}
_WIFI_MIME = b"application/vnd.wfa.wsc"
_AUTH_NAMES = {v: k for k, v in WIFI_AUTH.items()}
_ENC_NAMES = {v: k for k, v in WIFI_ENC.items()}


def _wsc_tlv(type_id, value):
    """WSC 속성 TLV(2바이트 type + 2바이트 length + value)를 생성."""
    return type_id.to_bytes(2, "big") + len(value).to_bytes(2, "big") + bytes(value)


def _wsc_walk(buf):
    """WSC TLV 목록을 [(type, value), ...]로 파싱."""
    out = []
    i = 0
    while i + 4 <= len(buf):
        t = int.from_bytes(buf[i:i + 2], "big")
        ln = int.from_bytes(buf[i + 2:i + 4], "big")
        out.append((t, buf[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def build_wifi_wsc(ssid, password, auth="WPA2-PSK", enc=None):
    """WiFi 접속정보를 WSC Credential 페이로드(bytes)로 생성."""
    auth_key = auth.upper() if isinstance(auth, str) else auth
    if auth_key not in WIFI_AUTH:
        raise ACR122UError(f"지원하지 않는 인증 방식: {auth}")
    if enc is None:
        enc_key = _DEFAULT_ENC[auth_key]
    else:
        enc_key = enc.upper() if isinstance(enc, str) else enc
    if enc_key not in WIFI_ENC:
        raise ACR122UError(f"지원하지 않는 암호화 방식: {enc}")

    cred = bytearray()
    cred += _wsc_tlv(_WSC_NETWORK_INDEX, b"\x01")
    cred += _wsc_tlv(_WSC_SSID, ssid.encode("utf-8"))
    cred += _wsc_tlv(_WSC_AUTH_TYPE, WIFI_AUTH[auth_key].to_bytes(2, "big"))
    cred += _wsc_tlv(_WSC_ENC_TYPE, WIFI_ENC[enc_key].to_bytes(2, "big"))
    if auth_key != "OPEN" and password:
        cred += _wsc_tlv(_WSC_NETWORK_KEY, password.encode("utf-8"))
    cred += _wsc_tlv(_WSC_MAC_ADDRESS, b"\x00" * 6)
    return _wsc_tlv(_WSC_CREDENTIAL, bytes(cred))


def build_wifi_wsc_ndef_tlv(ssid, password, auth="WPA2-PSK", enc=None):
    """WiFi WSC 레코드를 NDEF media-type 레코드로 만들어 TLV로 감싼 bytes를 반환."""
    payload = build_wifi_wsc(ssid, password, auth, enc)
    if len(payload) < 256:
        # 짧은 레코드: MB=ME=SR=1, TNF=002(media) → 0xD2
        record = bytes([0xD2, len(_WIFI_MIME), len(payload)]) + _WIFI_MIME + payload
    else:
        # 긴 레코드: SR=0 → 0xC2, 페이로드 길이 4바이트
        record = (bytes([0xC2, len(_WIFI_MIME)]) + len(payload).to_bytes(4, "big")
                  + _WIFI_MIME + payload)
    if len(record) < 255:
        return bytes([0x03, len(record)]) + record + bytes([0xFE])
    return bytes([0x03, 0xFF]) + len(record).to_bytes(2, "big") + record + bytes([0xFE])


def parse_wifi_wsc(payload):
    """WSC Credential 페이로드에서 ssid/password/auth/enc를 추출해 dict로 반환."""
    result = {}
    for t, v in _wsc_walk(payload):
        if t != _WSC_CREDENTIAL:
            continue
        for st, sv in _wsc_walk(v):
            if st == _WSC_SSID:
                result["ssid"] = sv.decode("utf-8", errors="replace")
            elif st == _WSC_NETWORK_KEY:
                result["password"] = sv.decode("utf-8", errors="replace")
            elif st == _WSC_AUTH_TYPE:
                code = int.from_bytes(sv, "big")
                result["auth"] = _AUTH_NAMES.get(code, f"0x{code:04X}")
            elif st == _WSC_ENC_TYPE:
                code = int.from_bytes(sv, "big")
                result["enc"] = _ENC_NAMES.get(code, f"0x{code:04X}")
    return result or None


def parse_wifi_from_tag(data):
    """태그에서 읽은 바이트열에서 WiFi WSC 레코드를 찾아 dict로 반환 (없으면 None)."""
    i = 0
    n = len(data)
    while i < n:
        t = data[i]
        if t == 0x00:
            i += 1
            continue
        if t == 0xFE:
            break
        if i + 1 >= n:
            break
        length = data[i + 1]
        idx = i + 2
        if length == 0xFF:  # 3바이트 길이 형식
            if i + 3 >= n:
                break
            length = int.from_bytes(bytes(data[i + 2:i + 4]), "big")
            idx = i + 4
        value = bytes(data[idx:idx + length])
        if t == 0x03:  # NDEF 메시지
            return _parse_wifi_record(value)
        i = idx + length
    return None


def _parse_wifi_record(rec):
    """NDEF 레코드에서 WiFi WSC 페이로드를 파싱."""
    if len(rec) < 3:
        return None
    header = rec[0]
    type_len = rec[1]
    short = bool(header & 0x10)   # SR
    has_id = bool(header & 0x08)  # IL
    idx = 2
    if short:
        payload_len = rec[idx]
        idx += 1
    else:
        payload_len = int.from_bytes(rec[idx:idx + 4], "big")
        idx += 4
    id_len = 0
    if has_id:
        id_len = rec[idx]
        idx += 1
    rec_type = rec[idx:idx + type_len]
    idx += type_len + id_len
    payload = rec[idx:idx + payload_len]
    if rec_type == _WIFI_MIME:
        return parse_wifi_wsc(payload)
    return None
