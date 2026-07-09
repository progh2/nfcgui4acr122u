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

from smartcard.System import readers
from smartcard.util import toHexString, toBytes  # noqa: F401  (toBytes는 외부에서 활용)
from smartcard.Exceptions import NoCardException, CardConnectionException


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
