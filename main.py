"""VirusTotal SHA-256 and URL scanner TUI."""

import os
from concurrent.futures import Future, ThreadPoolExecutor

import urwid
from dotenv import load_dotenv
import pyperclip

from virustotal import VirusTotal, VirusTotalError, extract_stats


PALETTE = [
    ("header", "white,bold", "dark blue"),
    ("title", "light cyan,bold", "default"),
    ("label", "white,bold", "default"),
    ("muted", "dark gray", "default"),
    ("ok", "light green,bold", "default"),
    ("warning", "yellow,bold", "default"),
    ("bad", "light red,bold", "default"),
    ("focus", "black,bold", "light cyan"),
]


class ScannerApp:
    def __init__(self):
        self.client = None
        self.mode = "hash"
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vt-scan")
        self.future: Future | None = None

        self.mode_group = []
        self.mode_hash = urwid.RadioButton(self.mode_group, "SHA-256", state=True, on_state_change=self._hash_selected)
        self.mode_url = urwid.RadioButton(self.mode_group, "URL", on_state_change=self._url_selected)
        self.input = urwid.Edit(multiline=False)
        self.value_label = urwid.Text(("label", "SHA-256"))
        self.status = urwid.Text(("muted", "Enter a SHA-256 hash and press Scan."))
        self.result_rows = urwid.SimpleFocusListWalker([
            urwid.Text(("muted", "Scan results will appear here.")),
        ])
        self.result_list = urwid.ListBox(self.result_rows)
        self.scan_button = urwid.Button("  Scan  ", on_press=self._scan)

        header = urwid.Pile([
            ("pack", urwid.AttrMap(urwid.Text("VIRUSTOTAL SCANNER", align="center"), "header")),
            ("pack", urwid.Text(("muted", "File and URL reputation checks with VirusTotal API v3"), align="center")),
        ])
        mode_box = self._section(
            urwid.Columns([self.mode_hash, self.mode_url], dividechars=4),
            " 1 · MODE ",
        )
        target_content = urwid.Pile([
            ("pack", self.value_label),
            ("pack", urwid.AttrMap(self.input, "", "focus")),
            ("pack", urwid.Text(("muted", "Ctrl+V / Shift+Insert to paste from clipboard"))),
        ])
        target_box = self._section(target_content, " 2 · SCAN TARGET ")
        action_box = self._section(
            urwid.AttrMap(self.scan_button, "", "focus"),
            " 3 · ACTION ",
        )
        status_box = self._section(self.status, " STATUS ")
        results_box = self._section(self.result_list, " REPORT ")
        self.pile = urwid.Pile([
            ("pack", header),
            ("pack", urwid.Divider()),
            ("pack", mode_box),
            ("pack", urwid.Divider()),
            ("pack", target_box),
            ("pack", urwid.Divider()),
            ("pack", action_box),
            ("pack", urwid.Divider()),
            ("pack", status_box),
            ("pack", urwid.Divider()),
            ("weight", 1, results_box),
            ("pack", urwid.Divider()),
            ("pack", urwid.Text(("muted", "Tab: navigate   Enter: select   Ctrl+C or Q: quit"))),
        ])
        frame = urwid.Padding(self.pile, left=2, right=2)
        self.loop = urwid.MainLoop(
            urwid.LineBox(frame, title=" VT SCANNER ", title_attr="title"),
            palette=PALETTE,
            unhandled_input=self._keypress,
        )

    @staticmethod
    def _section(widget, title):
        padded = urwid.Padding(widget, left=1, right=1)
        return urwid.LineBox(padded, title=title, title_attr="title")

    def _hash_selected(self, _button, state):
        if state:
            self._set_mode("hash")

    def _url_selected(self, _button, state):
        if state:
            self._set_mode("url")

    def _set_mode(self, mode):
        self.mode = mode
        self.value_label.set_text(("label", "SHA-256 hash" if mode == "hash" else "URL"))
        self.input.set_edit_text("")
        self.status.set_text(("muted", "Enter a SHA-256 hash and press Scan." if mode == "hash" else "Enter a full URL, including http:// or https://."))
        self.result_rows.clear()
        self.result_rows.append(urwid.Text(("muted", "Scan results will appear here.")))

    def _keypress(self, key):
        if key in ("ctrl v", "shift insert"):
            try:
                pasted = pyperclip.paste().replace("\r", " ").replace("\n", " ")
                if pasted:
                    before = self.input.edit_text[:self.input.edit_pos]
                    after = self.input.edit_text[self.input.edit_pos:]
                    self.input.set_edit_text(before + pasted + after)
                    self.input.set_edit_pos(len(before) + len(pasted))
            except pyperclip.PyperclipException as exc:
                self.status.set_text(("warning", f"Could not read the clipboard: {exc}"))
            return
        if key in ("ctrl c", "q"):
            raise urwid.ExitMainLoop()

    def _scan(self, _button):
        value = self.input.edit_text.strip()
        if not value:
            self.status.set_text(("warning", "Enter a SHA-256 hash or URL."))
            return
        if self.client is None:
            self.status.set_text(("bad", "VT_API_KEY is missing. Add your API key to the .env file."))
            return
        if self.future is not None:
            return

        scan = self.client.scan_hash if self.mode == "hash" else self.client.scan_url
        self.future = self.executor.submit(scan, value)
        self.scan_button.set_label("  Scanning…  ")
        self.status.set_text(("warning", "Request submitted. Waiting for VirusTotal…"))
        self.result_rows.clear()
        self.result_rows.append(urwid.Text(("muted", "Waiting for VirusTotal to finish the analysis…")))
        self.loop.set_alarm_in(0.2, self._check_scan)

    def _check_scan(self, _loop, _user_data):
        if self.future is None:
            return
        if not self.future.done():
            self.loop.set_alarm_in(0.2, self._check_scan)
            return

        future, self.future = self.future, None
        self.scan_button.set_label("  Scan  ")
        try:
            report = future.result()
            stats = extract_stats(report)
            if stats["malicious"]:
                verdict, style = f"Malicious detections: {stats['malicious']}", "bad"
            elif stats["suspicious"]:
                verdict, style = f"Suspicious detections: {stats['suspicious']}", "warning"
            else:
                verdict, style = "No malicious or suspicious detections.", "ok"
            self.status.set_text((style, verdict))
            self.result_rows.extend([
                urwid.Text((style, f"VERDICT  {verdict}")),
                urwid.Divider("─"),
                self._stat_row("Malicious", stats["malicious"], "bad"),
                self._stat_row("Suspicious", stats["suspicious"], "warning"),
                self._stat_row("Harmless", stats["harmless"], "ok"),
                self._stat_row("Undetected", stats["undetected"], "muted"),
            ])
        except VirusTotalError as exc:
            self.status.set_text(("warning", str(exc)))
        except Exception as exc:
            self.status.set_text(("bad", f"Unexpected error: {exc}"))

    @staticmethod
    def _stat_row(label, count, style):
        return urwid.Columns([
            ("weight", 1, urwid.Text((style, label))),
            ("pack", urwid.Text((style, str(count)), align="right")),
        ])

    def run(self):
        load_dotenv()
        key = os.environ.get("VT_API_KEY", "").strip()
        if key:
            try:
                self.client = VirusTotal(key)
            except VirusTotalError as exc:
                self.status.set_text(("bad", str(exc)))
        self.loop.run()
        self.executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    ScannerApp().run()
