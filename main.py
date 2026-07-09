"""
ACR122U NFC 리더/라이터 GUI (tkinter).

실행:  python main.py

필요 패키지:  pyscard   (pip install pyscard 또는 pip install -r requirements.txt)
Windows에서는 스마트카드 서비스가 실행 중이어야 하며(기본 켜짐),
ACR122U 드라이버(PC/SC)가 설치되어 있어야 합니다.
"""

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

try:
    from acr122u import ACR122U, ACR122UError
    PYSCARD_OK = True
    IMPORT_ERROR = ""
except ImportError as e:  # pyscard 미설치 등
    PYSCARD_OK = False
    IMPORT_ERROR = str(e)


POLL_INTERVAL = 0.4  # 카드 감지 주기(초)


class NFCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ACR122U NFC 리더/라이터")
        self.geometry("760x640")
        self.minsize(680, 560)

        self.nfc = ACR122U()
        self.lock = threading.Lock()          # 카드 접근 직렬화
        self.polling = False
        self.poll_thread = None
        self.current_uid = None
        self._last_info = None                 # 마지막으로 읽은 카드 정보 캐시
        self.ui_queue = queue.Queue()          # 백그라운드 → GUI 메시지 큐

        self._build_ui()
        self._refresh_readers()
        self.after(100, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================== #
    # UI 구성
    # ================================================================== #
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        # --- 상단: 리더 선택 / 연결 ---
        top = ttk.LabelFrame(self, text="리더 연결")
        top.pack(fill="x", **pad)

        ttk.Label(top, text="리더:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.reader_var = tk.StringVar()
        self.reader_combo = ttk.Combobox(
            top, textvariable=self.reader_var, width=48, state="readonly"
        )
        self.reader_combo.grid(row=0, column=1, sticky="we", padx=6, pady=6)
        ttk.Button(top, text="새로고침", command=self._refresh_readers).grid(
            row=0, column=2, padx=4
        )
        self.connect_btn = ttk.Button(top, text="연결", command=self._toggle_connect)
        self.connect_btn.grid(row=0, column=3, padx=6)
        top.columnconfigure(1, weight=1)

        # --- 카드 정보 ---
        info = ttk.LabelFrame(self, text="카드 정보")
        info.pack(fill="x", **pad)
        self.status_var = tk.StringVar(value="● 연결 안 됨")
        self.uid_var = tk.StringVar(value="-")
        self.type_var = tk.StringVar(value="-")
        self.atr_var = tk.StringVar(value="-")
        rows = [
            ("상태", self.status_var),
            ("UID", self.uid_var),
            ("카드 종류", self.type_var),
            ("ATR", self.atr_var),
        ]
        for i, (label, var) in enumerate(rows):
            ttk.Label(info, text=label + ":", width=10, anchor="e").grid(
                row=i, column=0, sticky="e", padx=6, pady=2
            )
            ttk.Label(info, textvariable=var, foreground="#0a5").grid(
                row=i, column=1, sticky="w", padx=6, pady=2
            )
        info.columnconfigure(1, weight=1)

        # --- 탭 ---
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, **pad)
        self._build_classic_tab(nb)
        self._build_ntag_tab(nb)
        self._build_text_tab(nb)
        self._build_device_tab(nb)

        # --- 로그 ---
        logf = ttk.LabelFrame(self, text="로그")
        logf.pack(fill="both", expand=True, **pad)
        self.log_text = tk.Text(logf, height=8, wrap="word", state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        sb = ttk.Scrollbar(logf, command=self.log_text.yview)
        sb.pack(side="right", fill="y", pady=6)
        self.log_text["yscrollcommand"] = sb.set

    def _build_classic_tab(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="MIFARE Classic")

        ttk.Label(f, text="키(16진수 12자리):").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.key_var = tk.StringVar(value="FFFFFFFFFFFF")
        ttk.Entry(f, textvariable=self.key_var, width=20).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(f, text="키 타입:").grid(row=0, column=2, sticky="e", padx=6)
        self.keytype_var = tk.StringVar(value="A")
        ttk.Combobox(
            f, textvariable=self.keytype_var, values=["A", "B"], width=4, state="readonly"
        ).grid(row=0, column=3, sticky="w", padx=6)

        ttk.Label(f, text="블록 번호:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.block_var = tk.StringVar(value="4")
        ttk.Entry(f, textvariable=self.block_var, width=8).grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(f, text="데이터(16진수 32자리 = 16바이트):").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 2)
        )
        self.classic_data_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.classic_data_var, width=52).grid(
            row=3, column=0, columnspan=4, sticky="we", padx=6
        )

        btns = ttk.Frame(f)
        btns.grid(row=4, column=0, columnspan=4, sticky="w", padx=6, pady=10)
        ttk.Button(btns, text="블록 읽기", command=self._classic_read).pack(side="left", padx=4)
        ttk.Button(btns, text="블록 쓰기", command=self._classic_write).pack(side="left", padx=4)

        ttk.Label(
            f,
            text="※ 기본 키 FFFFFFFFFFFF. 섹터 트레일러(3,7,11...)는 쓰기 주의!",
            foreground="#a60",
        ).grid(row=5, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 6))
        f.columnconfigure(3, weight=1)

    def _build_ntag_tab(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="NTAG / Ultralight")

        ttk.Label(f, text="페이지 번호:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.page_var = tk.StringVar(value="4")
        ttk.Entry(f, textvariable=self.page_var, width=8).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(f, text="데이터(16진수 8자리 = 4바이트):").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 2)
        )
        self.ntag_data_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.ntag_data_var, width=24).grid(
            row=2, column=0, columnspan=2, sticky="w", padx=6
        )

        btns = ttk.Frame(f)
        btns.grid(row=3, column=0, columnspan=3, sticky="w", padx=6, pady=10)
        ttk.Button(btns, text="페이지 읽기", command=self._ntag_read).pack(side="left", padx=4)
        ttk.Button(btns, text="페이지 쓰기", command=self._ntag_write).pack(side="left", padx=4)

        ttk.Label(
            f,
            text="※ NTAG21x는 페이지 0~3(UID/락)에 쓰지 마세요. 사용자 데이터는 4페이지부터.",
            foreground="#a60",
        ).grid(row=4, column=0, columnspan=3, sticky="w", padx=6)

    def _build_text_tab(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="텍스트 (NDEF)")

        ttk.Label(f, text="텍스트:").grid(row=0, column=0, sticky="ne", padx=6, pady=6)
        self.text_input = tk.Text(f, height=5, width=50, wrap="word")
        self.text_input.grid(row=0, column=1, columnspan=3, sticky="we", padx=6, pady=6)

        ttk.Label(f, text="언어코드:").grid(row=1, column=0, sticky="e", padx=6)
        self.lang_var = tk.StringVar(value="en")
        ttk.Entry(f, textvariable=self.lang_var, width=6).grid(row=1, column=1, sticky="w", padx=6)

        btns = ttk.Frame(f)
        btns.grid(row=2, column=0, columnspan=4, sticky="w", padx=6, pady=10)
        ttk.Button(btns, text="텍스트 읽기", command=self._text_read).pack(side="left", padx=4)
        ttk.Button(btns, text="텍스트 쓰기", command=self._text_write).pack(side="left", padx=4)

        ttk.Label(
            f,
            text="※ NTAG213/215/216 등 NDEF 지원 태그에서 동작합니다.",
            foreground="#a60",
        ).grid(row=3, column=0, columnspan=4, sticky="w", padx=6)
        f.columnconfigure(3, weight=1)

    def _build_device_tab(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="장치 제어")

        ttk.Button(f, text="펌웨어 버전 조회", command=self._firmware).grid(
            row=0, column=0, sticky="w", padx=6, pady=8
        )
        ttk.Button(f, text="삑 소리 (부저)", command=self._beep).grid(
            row=1, column=0, sticky="w", padx=6, pady=4
        )
        ttk.Button(f, text="인식음 켜기", command=lambda: self._buzzer_detect(True)).grid(
            row=2, column=0, sticky="w", padx=6, pady=4
        )
        ttk.Button(f, text="인식음 끄기", command=lambda: self._buzzer_detect(False)).grid(
            row=2, column=1, sticky="w", padx=6, pady=4
        )

    # ================================================================== #
    # 리더 / 연결
    # ================================================================== #
    def _refresh_readers(self):
        if not PYSCARD_OK:
            return
        try:
            names = ACR122U.list_readers()
        except Exception as e:
            names = []
            self.log(f"리더 검색 오류: {e}")
        self.reader_combo["values"] = names
        if names and not self.reader_var.get():
            # ACR122가 있으면 우선 선택
            default = next((n for n in names if "ACR122" in n), names[0])
            self.reader_var.set(default)
        self.log(f"리더 {len(names)}개 발견")

    def _toggle_connect(self):
        if self.polling:
            self._stop_polling()
        else:
            self._start_polling()

    def _start_polling(self):
        name = self.reader_var.get()
        if not name:
            messagebox.showwarning("리더 없음", "먼저 리더를 선택하세요.")
            return
        try:
            with self.lock:
                self.nfc.select_reader(name)
        except ACR122UError as e:
            messagebox.showerror("연결 오류", str(e))
            return
        self.polling = True
        self.current_uid = None
        self._last_info = None
        self.connect_btn["text"] = "연결 해제"
        self.status_var.set("● 카드 대기 중…")
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        self.log(f"'{name}' 감지 시작")

    def _stop_polling(self):
        self.polling = False
        self.connect_btn["text"] = "연결"
        self.status_var.set("● 연결 안 됨")
        self.uid_var.set("-")
        self.type_var.set("-")
        self.atr_var.set("-")
        self.current_uid = None
        self._last_info = None
        with self.lock:
            self.nfc.disconnect()
        self.log("감지 중지")

    def _poll_loop(self):
        """
        백그라운드에서 카드 삽입/제거를 감지.

        카드가 올라오면 '한 번만' 연결하고, 이후에는 가벼운 UID 재조회로 존재를
        확인한다(재연결하지 않으므로 RF 필드가 리셋되지 않아 깜빡임이 없다).
        일시적 통신 글리치는 연속 실패(디바운스)로 걸러 잘못된 '제거'를 막는다.
        """
        misses = 0
        while self.polling:
            info = None
            present = False
            with self.lock:
                try:
                    if not self.nfc.is_connected():
                        # 새 카드 감지 → 최초 1회 연결
                        self.nfc.connect()
                        self._last_info = {
                            "uid": self.nfc.get_uid(),
                            "type": self.nfc.identify_card(),
                            "atr": self.nfc.get_atr(),
                        }
                    else:
                        # 이미 연결됨 → UID만 재조회해 존재 확인 (필드 리셋 없음)
                        uid = self.nfc.get_uid()
                        if not self._last_info or uid != self._last_info["uid"]:
                            self._last_info = {
                                "uid": uid,
                                "type": self.nfc.identify_card(),
                                "atr": self.nfc.get_atr(),
                            }
                    present = True
                    info = self._last_info
                except Exception:
                    present = False

            if present:
                misses = 0
                if self.current_uid != info["uid"]:
                    self.current_uid = info["uid"]
                    self.ui_queue.put(("card", dict(info)))
            else:
                misses += 1
                # 연속 2회 이상 실패해야 실제 제거로 판정 (단발 글리치 무시)
                if misses >= 2 and self.current_uid is not None:
                    self.current_uid = None
                    with self.lock:
                        self.nfc.disconnect()
                    self.ui_queue.put(("card", None))
                elif misses >= 2:
                    # 카드가 아예 없는 상태: 다음 연결 시도를 위해 정리
                    with self.lock:
                        self.nfc.disconnect()
            time.sleep(POLL_INTERVAL)

    # ================================================================== #
    # 카드 작업 (버튼 핸들러) — lock으로 폴링과 직렬화
    # ================================================================== #
    def _ensure_card(self):
        """작업 전 카드 연결을 보장. 성공 시 True. 이미 연결돼 있으면 재사용(재연결 안 함)."""
        if not self.polling:
            messagebox.showwarning("연결 필요", "먼저 '연결' 버튼으로 감지를 시작하세요.")
            return False
        try:
            if not self.nfc.is_connected():
                self.nfc.connect()
            return True
        except Exception:
            messagebox.showwarning("카드 없음", "리더 위에 카드를 올려주세요.")
            return False

    def _classic_read(self):
        with self.lock:
            if not self._ensure_card():
                return
            try:
                block = int(self.block_var.get())
                data = self.nfc.read_classic_block(
                    block, self.key_var.get(), self.keytype_var.get()
                )
                hexstr = " ".join(f"{b:02X}" for b in data)
                self.classic_data_var.set("".join(f"{b:02X}" for b in data))
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                self.log(f"[Classic] 블록 {block} 읽기: {hexstr}  |  {ascii_str}")
            except (ACR122UError, ValueError) as e:
                self.log(f"[Classic] 읽기 오류: {e}")

    def _classic_write(self):
        data_str = self.classic_data_var.get().replace(" ", "")
        if len(data_str) != 32:
            messagebox.showwarning("입력 오류", "데이터는 16진수 32자리(16바이트)여야 합니다.")
            return
        with self.lock:
            if not self._ensure_card():
                return
            try:
                block = int(self.block_var.get())
                self.nfc.write_classic_block(
                    block, data_str, self.key_var.get(), self.keytype_var.get()
                )
                self.log(f"[Classic] 블록 {block} 쓰기 완료: {data_str}")
            except (ACR122UError, ValueError) as e:
                self.log(f"[Classic] 쓰기 오류: {e}")

    def _ntag_read(self):
        with self.lock:
            if not self._ensure_card():
                return
            try:
                page = int(self.page_var.get())
                data = self.nfc.read_block(page, 4)
                hexstr = "".join(f"{b:02X}" for b in data)
                self.ntag_data_var.set(hexstr)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                self.log(f"[NTAG] 페이지 {page} 읽기: {hexstr}  |  {ascii_str}")
            except (ACR122UError, ValueError) as e:
                self.log(f"[NTAG] 읽기 오류: {e}")

    def _ntag_write(self):
        data_str = self.ntag_data_var.get().replace(" ", "")
        if len(data_str) != 8:
            messagebox.showwarning("입력 오류", "데이터는 16진수 8자리(4바이트)여야 합니다.")
            return
        with self.lock:
            if not self._ensure_card():
                return
            try:
                page = int(self.page_var.get())
                self.nfc.write_block(page, data_str)
                self.log(f"[NTAG] 페이지 {page} 쓰기 완료: {data_str}")
            except (ACR122UError, ValueError) as e:
                self.log(f"[NTAG] 쓰기 오류: {e}")

    def _text_read(self):
        with self.lock:
            if not self._ensure_card():
                return
            try:
                text = self.nfc.read_ndef_text()
                if text is None:
                    self.log("[NDEF] 텍스트 레코드를 찾지 못했습니다.")
                else:
                    self.text_input.delete("1.0", "end")
                    self.text_input.insert("1.0", text)
                    self.log(f"[NDEF] 텍스트 읽기: {text!r}")
            except ACR122UError as e:
                self.log(f"[NDEF] 읽기 오류: {e}")

    def _text_write(self):
        text = self.text_input.get("1.0", "end-1c")
        if not text:
            messagebox.showwarning("입력 오류", "쓸 텍스트를 입력하세요.")
            return
        with self.lock:
            if not self._ensure_card():
                return
            try:
                pages = self.nfc.write_ndef_text(text, self.lang_var.get() or "en")
                self.log(f"[NDEF] 텍스트 쓰기 완료 ({pages}페이지): {text!r}")
            except ACR122UError as e:
                self.log(f"[NDEF] 쓰기 오류: {e}")

    def _firmware(self):
        with self.lock:
            if not self._ensure_card_or_reader():
                return
            try:
                ver = self.nfc.get_firmware_version()
                self.log(f"[장치] 펌웨어 버전: {ver}")
            except ACR122UError as e:
                self.log(f"[장치] 펌웨어 조회 오류: {e}")

    def _beep(self):
        with self.lock:
            if not self._ensure_card_or_reader():
                return
            try:
                self.nfc.beep()
                self.log("[장치] 부저 신호 전송")
            except ACR122UError as e:
                self.log(f"[장치] 부저 오류: {e}")

    def _buzzer_detect(self, enable):
        with self.lock:
            if not self._ensure_card_or_reader():
                return
            try:
                self.nfc.set_buzzer_on_detect(enable)
                self.log(f"[장치] 인식음 {'켜짐' if enable else '꺼짐'}")
            except ACR122UError as e:
                self.log(f"[장치] 부저 설정 오류: {e}")

    def _ensure_card_or_reader(self):
        """
        장치 명령(펌웨어/부저)은 카드가 없어도 리더에 대한 연결이 필요하다.
        ACR122U는 명령 전달을 위해 카드 연결(direct)이 필요하므로 카드를 요구한다.
        """
        if not self.polling:
            messagebox.showwarning("연결 필요", "먼저 '연결' 버튼으로 감지를 시작하세요.")
            return False
        try:
            if not self.nfc.is_connected():
                self.nfc.connect()
            return True
        except Exception:
            messagebox.showwarning("카드 없음", "장치 명령에도 리더 위 카드가 필요합니다. 카드를 올려주세요.")
            return False

    # ================================================================== #
    # GUI 큐 처리 / 로그
    # ================================================================== #
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "card":
                    self._update_card_info(payload)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _update_card_info(self, info):
        if info is None:
            self.status_var.set("● 카드 대기 중…")
            self.uid_var.set("-")
            self.type_var.set("-")
            self.atr_var.set("-")
        else:
            self.status_var.set("● 카드 감지됨")
            self.uid_var.set(info["uid"])
            self.type_var.set(info["type"])
            self.atr_var.set(info["atr"])
            self.log(f"카드 감지 — UID {info['uid']} ({info['type']})")

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_text["state"] = "normal"
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text["state"] = "disabled"

    def _on_close(self):
        self.polling = False
        try:
            with self.lock:
                self.nfc.disconnect()
        except Exception:
            pass
        self.destroy()


def main():
    if not PYSCARD_OK:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "pyscard 필요",
            "pyscard 라이브러리가 설치되어 있지 않습니다.\n\n"
            "터미널에서 다음을 실행하세요:\n"
            "    pip install pyscard\n\n"
            f"세부 오류: {IMPORT_ERROR}",
        )
        return
    app = NFCApp()
    app.mainloop()


if __name__ == "__main__":
    main()
