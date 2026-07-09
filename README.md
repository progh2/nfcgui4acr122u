# ACR122U NFC 리더/라이터 GUI

ACS **ACR122U** NFC 리더를 위한 파이썬 tkinter GUI 프로그램입니다.
카드 UID 자동 감지, MIFARE Classic 블록 읽기/쓰기, NTAG/Ultralight 페이지 읽기/쓰기,
NDEF 텍스트 읽기/쓰기, 부저·LED 제어를 지원합니다.

## 구성

| 파일 | 설명 |
|------|------|
| `acr122u.py` | pyscard 기반 ACR122U 장치 제어 래퍼 (APDU 로직) |
| `main.py` | tkinter GUI |
| `requirements.txt` | 의존성 (pyscard) |

## 요구 사항

- Windows / macOS / Linux + **ACR122U** 장치 및 PC/SC 드라이버
- Python 3.8+ (tkinter 포함 — 표준 배포판에 기본 포함)
- Windows: **Smart Card 서비스**(SCardSvr)가 실행 중이어야 함 (기본 자동 시작)

## 설치

```bash
pip install -r requirements.txt
```

> **Windows 참고:** `pip install pyscard`가 소스 빌드를 시도하며
> "Unable to find a compatible Visual Studio installation" 오류가 나면,
> 미리 빌드된 휠로 설치하세요:
>
> ```bash
> pip install --only-binary :all: pyscard
> ```

## 실행

```bash
python main.py
```

Windows에서는 `run.bat`을 더블클릭해도 됩니다.

## 사용법

1. 상단에서 리더(`ACS ACR122 0` 등)를 선택하고 **연결**을 누르면 카드 감지가 시작됩니다.
2. 카드를 리더 위에 올리면 **UID / 카드 종류 / ATR**이 자동 표시됩니다.
3. 탭에서 원하는 작업을 수행합니다.

### 탭 설명

- **MIFARE Classic** — 6바이트 키(기본 `FFFFFFFFFFFF`)로 인증 후 16바이트 블록 R/W
  - 섹터 트레일러(블록 3, 7, 11, …)에는 잘못 쓰면 섹터가 잠기니 주의하세요.
- **NTAG / Ultralight** — 4바이트 페이지 단위 R/W
  - 페이지 0~3(UID·락 비트)에는 쓰지 마세요. 사용자 데이터는 4페이지부터.
- **텍스트 (NDEF)** — NDEF Text 레코드로 문자열을 읽고 쓰기 (NTAG213/215/216 등)
- **장치 제어** — 펌웨어 버전 조회, 부저음, 카드 인식음 on/off

## APDU 참고 (acr122u.py에서 사용)

| 기능 | APDU |
|------|------|
| UID 읽기 | `FF CA 00 00 00` |
| 펌웨어 버전 | `FF 00 48 00 00` |
| 키 적재 | `FF 82 00 <slot> 06 <key6>` |
| 인증 | `FF 86 00 00 05 01 00 <block> <60/61> <slot>` |
| 블록 읽기 | `FF B0 00 <block> <len>` |
| 블록 쓰기 | `FF D6 00 <block> <len> <data>` |
| LED/부저 | `FF 00 40 <state> 04 <t1> <t2> <reps> <buzzer>` |
| 인식음 on/off | `FF 00 52 <FF/00> 00` |

## 주의

- 물리 카드가 없으면 대부분의 작업은 동작하지 않습니다(리더 위에 카드 필요).
- 쓰기 작업은 되돌릴 수 없습니다. 테스트용 카드로 먼저 확인하세요.
