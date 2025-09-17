#!/usr/bin/env python3
"""
run_ffuf_gui.py — Tkinter GUI wrapper for ffuf
Features:
 - Banner (SainiON Hacks)
 - Domain / Domain-list / Target-file modes
 - Wordlist auto-select / auto-download (git clone or raw)
 - Header controls (default headers toggles + custom headers)
 - Threads, recursion depth, follow redirects
 - Stream ffuf output to GUI text widget
 - Save combined results to TXT
"""

from __future__ import annotations
import sys
import os
import shutil
import subprocess
import threading
import queue
import datetime
import json
import difflib
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext

# ---------- Configuration ----------
BANNER_NAME = "SainiON Hacks"
BANNER_YT = "https://www.youtube.com/@sainionhacks"
BANNER_DETAILS = "Security tools & automation scripts. Subscribe for hacking tutorials and tooling."
SCRIPT_VERSION = "run_ffuf_gui v1.0"

SECLISTS_ROOT = Path("seclists")
SECLISTS_DIR = SECLISTS_ROOT / "Discovery" / "Web-Content"
RAW_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"

# default paths (heuristic)
DEFAULT_BIG = SECLISTS_DIR / "directory-list-2.3-big.txt"
DEFAULT_SMALL = SECLISTS_DIR / "common.txt"
DEFAULT_API = SECLISTS_DIR / "api.txt"

FCODES = "400,401,402,403,404,429,500,501,502,503"
EXTS = ".html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db"

DEFAULT_HEADERS_MAP = {
    "ua": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "xff": "X-Forwarded-For: 127.0.0.1",
    "origin": "X-Originating-IP: 127.0.0.1",
    "fhost": "X-Forwarded-Host: localhost",
}

# ---------- Utilities for wordlist detection/download ----------
def try_git_clone():
    """Clone SecLists into ./seclists if git available and seclists not present."""
    if shutil.which("git") and not SECLISTS_ROOT.exists():
        try:
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/danielmiessler/SecLists.git", str(SECLISTS_ROOT)], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    return False

def download_raw_file(target_path: Path) -> bool:
    filename = target_path.name
    url = f"{RAW_BASE}/{filename}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "python-urllib/3"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
            return True
    except Exception:
        return False

def find_candidates_in_seclists(basename: str) -> list[Path]:
    candidates = []
    if not SECLISTS_ROOT.exists():
        return candidates
    b_lower = basename.lower()
    for p in SECLISTS_ROOT.rglob("*"):
        if p.is_file():
            name = p.name.lower()
            if name == b_lower:
                candidates.insert(0, p)
            elif b_lower in name:
                candidates.append(p)
            else:
                candidates.append(p)
    return candidates

def choose_best_candidate(basename: str, candidates: list[Path]) -> Path | None:
    if not candidates:
        return None
    names = [p.name for p in candidates]
    best = difflib.get_close_matches(basename, names, n=1, cutoff=0.6)
    if best:
        idx = names.index(best[0])
        return candidates[idx]
    for p in candidates:
        n = p.name.lower()
        if "directory" in n or "list" in n or "big" in n or "common" in n:
            return p
    return candidates[0]

def ensure_wordlist(path: Path) -> Path | None:
    """Return resolved Path if found or downloaded, otherwise None."""
    if path.exists():
        return path
    # try clone
    try_git_clone()
    if path.exists():
        return path
    # search seclists
    basename = path.name
    candidates = find_candidates_in_seclists(basename)
    if candidates:
        best = choose_best_candidate(basename, candidates)
        return best
    # fallback raw download (best-effort)
    if download_raw_file(path):
        return path
    return None

# ---------- ffuf command builder ----------
def build_ffuf_cmd(wordlist: Path, target: str, threads: int, depth: int, follow: bool, headers: list[str]) -> list[str]:
    cmd = [
        "ffuf",
        "-w", str(wordlist),
        "-u", target,
        "-fc", FCODES,
        "-recursion", "-recursion-depth", str(depth),
        "-e", EXTS,
        "-ac", "-c",
        "-t", str(threads)
    ]
    if follow:
        cmd += ["-r"]
    for h in headers:
        cmd += ["-H", h]
    # do not include -o, we'll stream output
    return cmd

# ---------- GUI Application ----------
class FFUFGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("run_ffuf — SainiON Hacks")
        self.geometry("1000x720")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.proc = None
        self.proc_thread = None
        self.output_queue = queue.Queue()
        self.results = {}  # target -> {"rc": int, "output": str}
        self.buffer_lock = threading.Lock()

        self.build_ui()
        self.after(200, self._poll_output_queue)

    def build_ui(self):
        # Banner frame
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        banner_title = tk.Label(top, text=BANNER_NAME, font=("Consolas", 20, "bold"), fg="#00cc44")
        banner_title.pack(side=tk.TOP)
        banner_link = tk.Label(top, text=BANNER_YT + "  —  " + BANNER_DETAILS, font=("Consolas", 9), fg="#00cc44")
        banner_link.pack(side=tk.TOP)

        # Main panes
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left control frame
        left = ttk.Frame(main_pane, width=360)
        main_pane.add(left, weight=0)

        # Mode selection
        mode_frame = ttk.LabelFrame(left, text="Mode")
        mode_frame.pack(fill=tk.X, pady=4)
        self.mode_var = tk.StringVar(value="domain")
        ttk.Radiobutton(mode_frame, text="Single domain", variable=self.mode_var, value="domain").pack(anchor=tk.W, padx=6, pady=2)
        ttk.Radiobutton(mode_frame, text="Domain list (file)", variable=self.mode_var, value="domain-list").pack(anchor=tk.W, padx=6, pady=2)
        ttk.Radiobutton(mode_frame, text="Target / Targets file", variable=self.mode_var, value="target").pack(anchor=tk.W, padx=6, pady=2)

        # Target entry / browse
        target_frame = ttk.LabelFrame(left, text="Target / File")
        target_frame.pack(fill=tk.X, pady=4)
        self.target_entry = ttk.Entry(target_frame)
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=6)
        ttk.Button(target_frame, text="Browse", command=self.browse_target_file).pack(side=tk.RIGHT, padx=6)

        # Wordlist selection
        wl_frame = ttk.LabelFrame(left, text="Wordlist")
        wl_frame.pack(fill=tk.X, pady=4)
        self.wordlist_entry = ttk.Entry(wl_frame)
        self.wordlist_entry.pack(side=tk.TOP, fill=tk.X, padx=6, pady=4)
        wl_buttons = ttk.Frame(wl_frame)
        wl_buttons.pack(fill=tk.X, padx=6)
        ttk.Button(wl_buttons, text="Auto-select / Download", command=self.auto_select_wordlist).pack(side=tk.LEFT, padx=2)
        ttk.Button(wl_buttons, text="Browse", command=self.browse_wordlist).pack(side=tk.LEFT, padx=2)
        ttk.Button(wl_buttons, text="Use default big", command=lambda: self.wordlist_entry.insert(0, str(DEFAULT_BIG))).pack(side=tk.LEFT, padx=2)

        # Header controls
        header_frame = ttk.LabelFrame(left, text="Headers")
        header_frame.pack(fill=tk.X, pady=4)
        self.h_no_headers = tk.BooleanVar(value=False)
        ttk.Checkbutton(header_frame, text="Disable all default headers", variable=self.h_no_headers).pack(anchor=tk.W, padx=6, pady=2)
        # individual toggles
        self.h_ua = tk.BooleanVar(value=True)
        self.h_xff = tk.BooleanVar(value=True)
        self.h_origin = tk.BooleanVar(value=True)
        self.h_fhost = tk.BooleanVar(value=True)
        ttk.Checkbutton(header_frame, text="User-Agent", variable=self.h_ua).pack(anchor=tk.W, padx=18)
        ttk.Checkbutton(header_frame, text="X-Forwarded-For", variable=self.h_xff).pack(anchor=tk.W, padx=18)
        ttk.Checkbutton(header_frame, text="X-Originating-IP", variable=self.h_origin).pack(anchor=tk.W, padx=18)
        ttk.Checkbutton(header_frame, text="X-Forwarded-Host", variable=self.h_fhost).pack(anchor=tk.W, padx=18)

        # custom headers list
        ch_frame = ttk.Frame(header_frame)
        ch_frame.pack(fill=tk.X, pady=4, padx=6)
        self.custom_header_entry = ttk.Entry(ch_frame)
        self.custom_header_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ch_frame, text="Add", command=self.add_custom_header).pack(side=tk.LEFT, padx=4)
        ttk.Button(ch_frame, text="Remove Selected", command=self.remove_custom_header).pack(side=tk.LEFT, padx=4)
        self.custom_headers_listbox = tk.Listbox(header_frame, height=4)
        self.custom_headers_listbox.pack(fill=tk.X, padx=6, pady=4)

        # Threads / depth / follow
        opt_frame = ttk.LabelFrame(left, text="Options")
        opt_frame.pack(fill=tk.X, pady=4)
        row = ttk.Frame(opt_frame)
        row.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(row, text="Threads:").pack(side=tk.LEFT)
        self.threads_var = tk.IntVar(value=100)
        ttk.Entry(row, textvariable=self.threads_var, width=6).pack(side=tk.LEFT, padx=6)
        ttk.Label(row, text="Recursion depth:").pack(side=tk.LEFT, padx=6)
        self.depth_var = tk.IntVar(value=2)
        ttk.Entry(row, textvariable=self.depth_var, width=4).pack(side=tk.LEFT)
        self.follow_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Follow redirects (-r)", variable=self.follow_var).pack(anchor=tk.W, padx=6, pady=4)

        # Control buttons
        ctrl_frame = ttk.Frame(left)
        ctrl_frame.pack(fill=tk.X, pady=6, padx=6)
        self.start_btn = ttk.Button(ctrl_frame, text="Start Scan", command=self.on_start)
        self.start_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        self.stop_btn = ttk.Button(ctrl_frame, text="Stop Scan", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(ctrl_frame, text="Save Results (TXT)", command=self.on_save_results).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_frame, text="Instructions", command=self.show_instructions).pack(side=tk.LEFT, padx=2)

        # Right output area
        right = ttk.Frame(main_pane)
        main_pane.add(right, weight=1)

        out_label = ttk.Label(right, text="Live output:")
        out_label.pack(anchor=tk.W, padx=6)
        self.output_text = scrolledtext.ScrolledText(right, wrap=tk.NONE, font=("Consolas", 9))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------- UI callbacks ----------
    def browse_target_file(self):
        mode = self.mode_var.get()
        if mode == "domain-list" or mode == "target":
            path = filedialog.askopenfilename(title="Select file", filetypes=[("Text files", "*.txt;*.lst;*.list"), ("All files", "*.*")])
            if path:
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, path)
        else:
            # domain mode: allow user to paste domain or URL
            domain = simpledialog.askstring("Domain", "Enter domain (example.com or https://example.com):")
            if domain:
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, domain)

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def auto_select_wordlist(self):
        # choose heuristic default based on mode
        mode = self.mode_var.get()
        suggested = DEFAULT_BIG if (mode in ("file", "domain-list")) else DEFAULT_BIG
        # try to resolve
        resolved = ensure_wordlist(Path(suggested))
        if resolved:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, str(resolved))
            messagebox.showinfo("Wordlist", f"Using wordlist: {resolved}")
        else:
            messagebox.showwarning("Wordlist", "Could not auto-obtain wordlist. Please browse or check network/git.")

    def add_custom_header(self):
        txt = self.custom_header_entry.get().strip()
        if not txt:
            return
        if ":" not in txt:
            messagebox.showwarning("Header", "Custom header must include ':' (Name: value).")
            return
        self.custom_headers_listbox.insert(tk.END, txt)
        self.custom_header_entry.delete(0, tk.END)

    def remove_custom_header(self):
        sel = list(self.custom_headers_listbox.curselection())
        for i in reversed(sel):
            self.custom_headers_listbox.delete(i)

    def show_instructions(self):
        txt = (
            "Instructions:\n\n"
            "1) Choose mode: Single domain will be converted to https://<domain>/FUZZ\n"
            "2) For domain-list or targets file, browse and select a file with one entry per line\n"
            "3) Use 'Auto-select / Download' to try to fetch SecLists if missing\n"
            "4) Configure headers / threads / recursion depth\n"
            "5) Click Start Scan to run ffuf and stream output here\n"
            "6) After runs, click 'Save Results (TXT)' to export combined output\n\n"
            "Only scan targets you have authorization to test."
        )
        messagebox.showinfo("Instructions", txt)

    def set_status(self, message: str):
        self.status_var.set(message)

    # ---------- ffuf run logic ----------
    def _poll_output_queue(self):
        try:
            while True:
                line = self.output_queue.get_nowait()
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
        except queue.Empty:
            pass
        self.after(200, self._poll_output_queue)

    def on_start(self):
        # ensure ffuf
        if shutil.which("ffuf") is None:
            messagebox.showerror("ffuf not found", "ffuf not found in PATH. Please install ffuf before running.")
            return

        target_val = self.target_entry.get().strip()
        if not target_val:
            messagebox.showwarning("No target", "Please enter a domain / target / file path.")
            return

        # resolve wordlist
        wl_txt = self.wordlist_entry.get().strip()
        chosen_wl = Path(wl_txt) if wl_txt else DEFAULT_BIG
        resolved_wl = ensure_wordlist(chosen_wl)
        if resolved_wl is None:
            # ask user whether to continue without wordlist
            if not messagebox.askyesno("Wordlist missing", "Could not find or download the requested wordlist.\nContinue without running?"):
                return
        else:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, str(resolved_wl))

        # prepare headers
        headers = []
        if not self.h_no_headers.get():
            if self.h_ua.get():
                headers.append(DEFAULT_HEADERS_MAP["ua"])
            if self.h_xff.get():
                headers.append(DEFAULT_HEADERS_MAP["xff"])
            if self.h_origin.get():
                headers.append(DEFAULT_HEADERS_MAP["origin"])
            if self.h_fhost.get():
                headers.append(DEFAULT_HEADERS_MAP["fhost"])
        # custom headers
        for i in range(self.custom_headers_listbox.size()):
            headers.append(self.custom_headers_listbox.get(i))

        # target mode
        mode = self.mode_var.get()
        targets = []
        if mode == "domain":
            targets = [self.domain_to_target(target_val)]
        elif mode == "domain-list":
            path = Path(target_val)
            if not path.is_file():
                messagebox.showerror("File not found", "Domain list file not found. Please browse to a valid file.")
                return
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    s = line.strip()
                    if s:
                        targets.append(self.domain_to_target(s))
        else:  # target mode
            # if it's a file of targets, read; else single target
            path = Path(target_val)
            if path.is_file():
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        if "FUZZ" not in s:
                            s = s.rstrip("/") + "/FUZZ"
                        targets.append(s)
            else:
                t = target_val
                if "FUZZ" not in t:
                    t = t.rstrip("/") + "/FUZZ"
                targets.append(t)

        if not targets:
            messagebox.showwarning("No targets", "No targets resolved. Check input.")
            return

        # disable start, enable stop
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.set_status("Running...")
        self.output_text.insert(tk.END, f"\n--- Scan started at {datetime.datetime.utcnow().isoformat()}Z ---\n")
        self.output_text.see(tk.END)

        # run in background thread
        self.proc_thread = threading.Thread(target=self._run_targets_seq, args=(targets, resolved_wl or chosen_wl, headers, int(self.threads_var.get()), int(self.depth_var.get()), bool(self.follow_var.get())))
        self.proc_thread.daemon = True
        self.proc_thread.start()

    def on_stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.set_status("Terminated")
                self.output_text.insert(tk.END, "\n[!] Scan terminated by user.\n")
            except Exception as e:
                print("Stop error:", e)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def _run_targets_seq(self, targets: list[str], wordlist: Path, headers: list[str], threads: int, depth: int, follow: bool):
        # sequentially run ffuf for each target, stream output, buffer results
        for target in targets:
            if self.proc and self.proc.poll() is None:
                # if existing process running, wait / continue
                pass
            cmd = build_ffuf_cmd(wordlist, target, threads, depth, follow, headers)
            self.output_queue.put(f"\n[+] Running: {' '.join(cmd)}\n\n")
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            except Exception as e:
                self.output_queue.put(f"[!] Failed to start ffuf: {e}\n")
                continue

            captured_lines = []
            try:
                assert self.proc.stdout is not None
                for line in self.proc.stdout:
                    captured_lines.append(line)
                    self.output_queue.put(line)
                self.proc.wait()
                rc = self.proc.returncode if self.proc.returncode is not None else -1
            except Exception as e:
                self.output_queue.put(f"[!] Error during ffuf run: {e}\n")
                rc = -1
            # store results
            with self.buffer_lock:
                self.results[target] = {"rc": rc, "output": "".join(captured_lines)}
            self.output_queue.put(f"\n[+] Finished {target} (rc={rc})\n")

        # finished all
        self.proc = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.set_status("Idle")
        self.output_queue.put(f"\n--- All scans finished at {datetime.datetime.utcnow().isoformat()}Z ---\n")

    def domain_to_target(self, domain_line: str) -> str:
        s = domain_line.strip()
        if not s:
            return ""
        if "FUZZ" in s:
            return s
        if "://" in s:
            if s.endswith("/"):
                return s + "FUZZ"
            else:
                return s + ("/FUZZ" if "FUZZ" not in s else "")
        return f"https://{s.rstrip('/')}/FUZZ"

    def on_save_results(self):
        if not self.results:
            messagebox.showinfo("No results", "No captured results to save.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")], initialfile="results.txt")
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                header = f"{BANNER_NAME} | {BANNER_YT}\n{BANNER_DETAILS}\nScript: {SCRIPT_VERSION}\nSaved: {datetime.datetime.utcnow().isoformat()}Z\n\n"
                fh.write(header)
                fh.write("="*80 + "\n\n")
                with self.buffer_lock:
                    for target, info in self.results.items():
                        fh.write(f"TARGET: {target}\n")
                        fh.write(f"Return code: {info.get('rc')}\n")
                        fh.write("-"*60 + "\n")
                        fh.write(info.get("output","") + "\n\n")
                        fh.write("="*80 + "\n\n")
            messagebox.showinfo("Saved", f"Results saved to: {filename}")
        except Exception as e:
            messagebox.showerror("Save error", f"Failed to write file: {e}")

    def on_close(self):
        if self.proc and self.proc.poll() is None:
            if not messagebox.askyesno("Exit", "ffuf is running. Stop and exit?"):
                return
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.destroy()

# ---------- main ----------
def main():
    app = FFUFGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
