#!/usr/bin/env python3
"""
run_ffuf.py — Interactive ffuf runner with quick menu

When run with NO command-line arguments the script shows a 3-option menu:
  1) Target      -> Start an interactive target scan (domain / domain-list / target file)
  2) Instructions-> Show quick instructions and examples
  3) Exit        -> Quit

If you prefer CLI usage, pass the same flags as before (script will skip menu).
"""
from __future__ import annotations
import argparse
import shutil
import subprocess
import sys
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import datetime
import json
import difflib
from typing import Optional, List, Dict

# ====== Banner / attribution (customize) ======
BANNER_NAME = "SainiON Hacks"
BANNER_YT = "https://www.youtube.com/@sainionhacks"
BANNER_DETAILS = "Security tools & automation scripts. Subscribe for hacking tutorials and tooling."
# =================================================

# ===== Configuration / defaults =====
SECLISTS_ROOT = Path("seclists")
SECLISTS_DIR = SECLISTS_ROOT / "Discovery" / "Web-Content"
BIG = SECLISTS_DIR / "directory-list-2.3-big.txt"
SMALL = SECLISTS_DIR / "common.txt"
API = SECLISTS_DIR / "api.txt"
RAW_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"

FCODES = "400,401,402,403,404,429,500,501,502,503"
EXTS = ".html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db"

DEFAULT_HEADERS_MAP: Dict[str, str] = {
    "ua": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "xff": "X-Forwarded-For: 127.0.0.1",
    "origin": "X-Originating-IP: 127.0.0.1",
    "fhost": "X-Forwarded-Host: localhost",
}

SCRIPT_VERSION = "run_ffuf.py v1.7 (menu + headers control + streaming + optional-txt-save)"

# ===== Helpers (wordlist, ffuf, banner, run) =====
def print_banner():
    GREEN = "\033[1;32m"
    RESET = "\033[0m"
    art = r"""
 .----------------.  .----------------.  .----------------.  .----------------.
 
 _____       _       _ _____ _   _   _   _            _        
/  ___|     (_)     (_)  _  | \ | | | | | |          | |       
\ `--.  __ _ _ _ __  _| | | |  \| | | |_| | __ _  ___| | _____ 
 `--. \/ _` | | '_ \| | | | | . ` | |  _  |/ _` |/ __| |/ / __|
/\__/ / (_| | | | | | \ \_/ / |\  | | | | | (_| | (__|   <\__ \
\____/ \__,_|_|_| |_|_|\___/\_| \_/ \_| |_/\__,_|\___|_|\_\___/
                                                               
                                                               
                                                               
                                                               
 '----------------'  '----------------'  '----------------'  '----------------'
"""
    title = f"              {BANNER_NAME}"
    yt = f"      YT: {BANNER_YT}"
    print("\n".join([GREEN + art + RESET, GREEN + title + RESET, GREEN + yt + RESET, ""]))

def ensure_ffuf():
    if shutil.which("ffuf") is None:
        print("Error: ffuf not found in PATH. Please install ffuf.", file=sys.stderr)
        sys.exit(2)

def try_git_clone() -> bool:
    if shutil.which("git") and not SECLISTS_ROOT.exists():
        print("[*] git found — cloning SecLists (depth=1). This may take a moment...")
        try:
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/danielmiessler/SecLists.git", str(SECLISTS_ROOT)], check=True)
            return True
        except subprocess.CalledProcessError:
            print("[!] git clone failed, will try direct download / search fallback.")
    return False

def download_raw_file(target_path: Path) -> bool:
    filename = target_path.name
    url = f"{RAW_BASE}/{filename}"
    print(f"[*] Attempting direct download: {url}")
    try:
        req = Request(url, headers={"User-Agent": "python-urllib/3"})
        with urlopen(req, timeout=30) as resp:
            data = resp.read()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
            print(f"[+] Downloaded {filename} -> {target_path}")
            return True
    except (HTTPError, URLError, Exception) as e:
        print(f"[!] Download failed: {e}")
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

def ensure_wordlist(path: Path, user_requested_basename: str | None = None) -> Path | None:
    if path.exists():
        return path
    cloned = try_git_clone()
    if path.exists():
        return path
    basename = user_requested_basename or path.name
    candidates = find_candidates_in_seclists(basename)
    if candidates:
        best = choose_best_candidate(basename, candidates)
        if best:
            print(f"[*] Found best match in seclists: {best}")
            return best
    if download_raw_file(path):
        return path
    return None

def prompt(text: str, default: str | None = None, yes: bool = False) -> str:
    if yes:
        return default or ""
    if default is not None:
        r = input(f"{text} [{default}]: ").strip()
        return r if r else default
    return input(f"{text}: ").strip()

def auto_select_wordlist(mode: str, target_str: str | None) -> Path:
    if mode == "file":
        if BIG.exists(): return BIG
        if SMALL.exists(): return SMALL
        return BIG
    t = (target_str or "").lower()
    if "api" in t and API.exists():
        return API
    if BIG.exists(): return BIG
    if SMALL.exists(): return SMALL
    return BIG

def choose_wordlist_interactive(mode: str, target_str: str | None, yes: bool = False, initial_choice: str | None = None) -> Path:
    if initial_choice:
        return Path(initial_choice)
    if yes:
        return auto_select_wordlist(mode, target_str)
    candidates = []
    if BIG.exists(): candidates.append(("Big - directory-list-2.3-big.txt", str(BIG)))
    if SMALL.exists(): candidates.append(("Small - common.txt", str(SMALL)))
    if API.exists(): candidates.append(("API - api.txt", str(API)))
    candidates.append(("Custom path", "custom"))
    candidates.append(("Auto-select (recommended)", "auto"))

    print("\nWordlist options:")
    for i, (name, path) in enumerate(candidates, 1):
        print(f" {i}) {name} {('- ' + path) if path!='custom' else ''}")
    choice = input("Pick number (Enter for Auto-select): ").strip()
    if choice == "":
        return auto_select_wordlist(mode, target_str)
    try:
        sel = int(choice) - 1
        sel_val = candidates[sel][1]
    except Exception:
        print("Invalid selection, falling back to auto-select.")
        return auto_select_wordlist(mode, target_str)

    if sel_val == "custom":
        cp = input("Enter custom wordlist path: ").strip()
        return Path(cp)
    if sel_val == "auto":
        return auto_select_wordlist(mode, target_str)
    return Path(sel_val)

def build_ffuf_cmd(wordlist: Path, target: str, threads: int, depth: int, follow: bool, headers: List[str]) -> list:
    cmd = [
        "ffuf",
        "-w", str(wordlist),
        "-u", target,
        "-fc", FCODES,
        "-recursion", "-recursion-depth", str(depth),
        "-e", EXTS,
        "-ac", "-c"
    ]
    for h in headers:
        cmd += ["-H", h]
    cmd += ["-t", str(threads)]
    if follow:
        cmd += ["-r"]
    return cmd

def stream_run_and_capture(cmd: list) -> tuple[int, str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    captured_lines = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            captured_lines.append(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        print("\n[!] Scan interrupted by user.")
    return proc.returncode if proc.returncode is not None else -1, "".join(captured_lines)

def domain_to_target(domain_line: str) -> str:
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

def find_and_resolve_wordlist(chosen: Path) -> Optional[Path]:
    return ensure_wordlist(chosen, user_requested_basename=chosen.name)

def ask_and_save_combined(results: dict[str, dict], chosen_wordlist: Path):
    if not results:
        print("[*] No results captured; nothing to save.")
        return
    ans = input("\nSave combined results to TXT? (y/N): ").strip().lower()
    if ans not in ("y", "yes"):
        print("Not saving results.")
        return
    default = "results.txt"
    filename = input(f"Output TXT filename [{default}]: ").strip() or default
    out_path = Path(filename)
    try:
        with out_path.open("w", encoding="utf-8") as fh:
            header = f"{BANNER_NAME} | {BANNER_YT}\n{BANNER_DETAILS}\nScript: {SCRIPT_VERSION}\nWordlist: {chosen_wordlist}\nGenerated: {datetime.datetime.utcnow().isoformat()}Z\n\n"
            fh.write(header)
            fh.write("="*80 + "\n\n")
            for target, info in results.items():
                fh.write(f"TARGET: {target}\n")
                fh.write(f"Return code: {info.get('rc')}\n")
                fh.write("-"*60 + "\n")
                fh.write(info.get("output", "") + "\n")
                fh.write("\n" + "="*80 + "\n\n")
        print(f"[+] Combined results saved to {out_path}")
    except Exception as e:
        print(f"[!] Failed to write {out_path}: {e}", file=sys.stderr)

# ===== Interactive flows & menu =====
def run_scan_flow_interactive(pre_args: argparse.Namespace | None = None):
    """Interactive flow to ask for target mode, wordlist, headers then run scans and optionally save."""
    # If pre_args passed (from CLI), honor those; otherwise prompt interactively
    if pre_args:
        args = pre_args
    else:
        # minimal args container with defaults
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--threads", type=int, default=100)
        parser.add_argument("--depth", type=int, default=2)
        parser.add_argument("--follow", action="store_true", default=False)
        parser.add_argument("--yes", action="store_true", default=False)
        tmp = parser.parse_args([])
        args = tmp

    # Prompt for source type
    print("\nChoose source type:")
    print("  1) Single domain (example.com) -> https://example.com/FUZZ")
    print("  2) Domain list file (one domain per line)")
    print("  3) Target URL or file (full URL with optional FUZZ or file of targets)")
    choice = input("Select 1/2/3 [1]: ").strip() or "1"

    if choice == "1":
        domain = input("Enter domain (example.com or https://example.com): ").strip()
        source_mode = "domain"
        source_value = domain
    elif choice == "2":
        path = input("Enter path to domain list file: ").strip()
        source_mode = "domain-list"
        source_value = path
    else:
        t = input("Enter target URL (include FUZZ) or path to file of targets: ").strip()
        if Path(t).is_file():
            source_mode = "file"
        else:
            source_mode = "single"
        source_value = t

    # Wordlist selection
    chosen = choose_wordlist_interactive(mode="file" if source_mode in ("file", "domain-list") else "single",
                                         target_str=source_value if isinstance(source_value, str) else None,
                                         yes=args.yes,
                                         initial_choice=None)
    if not isinstance(chosen, Path):
        chosen = Path(chosen)
    if not chosen:
        chosen = BIG
    resolved = find_and_resolve_wordlist(chosen)
    if resolved is None:
        print(f"Error: could not obtain or locate a wordlist matching '{chosen}'. Aborting scan.")
        return
    print(f"[+] Using wordlist: {resolved}")

    # Header controls (interactive)
    headers: List[str] = list(DEFAULT_HEADERS_MAP.values())
    use_defaults = input("Use default headers? (Y/n): ").strip().lower()
    if use_defaults in ("n", "no"):
        headers = []
        print("Enter custom headers one per line (Name: value). Empty line to finish.")
        while True:
            line = input().strip()
            if not line:
                break
            if ":" not in line:
                print("Invalid header (missing ':'). Try again.")
                continue
            headers.append(line)
    print("\n[+] Headers to use:")
    if headers:
        for h in headers:
            print("   " + h)
    else:
        print("   (none)")

    # Run scans and collect results
    results: dict[str, dict] = {}
    threads = args.threads
    depth = args.depth
    follow = args.follow

    def do_run_for_target(target: str):
        print(f"\n[+] Running ffuf against: {target}\n")
        cmd = build_ffuf_cmd(resolved, target, threads, depth, follow, headers)
        rc, output = stream_run_and_capture(cmd)
        results[target] = {"rc": rc, "output": output}

    if source_mode == "domain":
        target = domain_to_target(source_value)
        do_run_for_target(target)
    elif source_mode == "domain-list":
        list_path = Path(source_value)
        if not list_path.is_file():
            print(f"Error: domain-list file not found: {list_path}")
            return
        with list_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = line.strip()
                if not d:
                    continue
                target = domain_to_target(d)
                do_run_for_target(target)
    elif source_mode == "file":
        tgt_file = Path(source_value)
        if not tgt_file.is_file():
            print(f"Error: target file not found: {tgt_file}")
            return
        with tgt_file.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip()
                if not t:
                    continue
                if "FUZZ" not in t:
                    t = t.rstrip("/") + "/FUZZ"
                do_run_for_target(t)
    elif source_mode == "single":
        t = source_value
        if "FUZZ" not in t:
            t = t.rstrip("/") + "/FUZZ"
        do_run_for_target(t)

    # After scans, ask to save combined results
    ask_and_save_combined(results, resolved)
    print("\nReturning to menu...\n")

def print_instructions():
    print("\n=== Instructions & Examples ===\n")
    print("This script runs ffuf with friendly interactive options and smart SecLists fetching.")
    print("Menu options:")
    print(" 1) Target      -> Run a scan interactively (choose domain / domain-list / target file)")
    print(" 2) Instructions-> Show this help text")
    print(" 3) Exit        -> Quit\n")
    print("CLI usage examples (skip menu):")
    print("  python3 run_ffuf.py -d example.com")
    print("  python3 run_ffuf.py -dL domains.txt")
    print("  python3 run_ffuf.py --target 'https://example.com/FUZZ'")
    print("\nHeader control flags (CLI):")
    print("  --no-headers  --no-ua  --no-xff  --no-originating  --no-forwarded-host  -H 'Name: Value'\n")
    print("After any scan the script prints live ffuf output and then asks if you want to save combined results to a TXT file.")
    print("Only scan targets you are authorized to test.\n")

# ===== CLI runner (previous behavior) =====
def run_with_args(args: argparse.Namespace):
    """Run script using parsed CLI args (non-interactive unless prompting for headers)."""
    # Ensure ffuf
    ensure_ffuf()

    # Determine source priority: domain -> domain-list -> target
    source_mode = None
    source_value = None
    if getattr(args, "domain", None):
        source_mode = "domain"
        source_value = args.domain.strip()
    elif getattr(args, "domain_list", None):
        source_mode = "domain-list"
        source_value = args.domain_list.strip()
    elif getattr(args, "target", None):
        if Path(args.target).is_file():
            source_mode = "file"
        else:
            source_mode = "single"
        source_value = args.target.strip()
    else:
        print("[!] No target specified. Use the menu or pass --target/-d/-dL.")
        return

    # Wordlist selection
    chosen = choose_wordlist_interactive(mode="file" if source_mode in ("file", "domain-list") else "single",
                                         target_str=source_value if isinstance(source_value, str) else None,
                                         yes=args.yes,
                                         initial_choice=args.wordlist)
    if not isinstance(chosen, Path):
        chosen = Path(chosen)
    if not chosen:
        chosen = BIG

    resolved = find_and_resolve_wordlist(chosen)
    if resolved is None:
        print(f"Error: could not obtain or locate a wordlist matching '{chosen}'. Aborting.", file=sys.stderr)
        return
    else:
        print(f"[+] Using wordlist: {resolved}")

    # Headers build
    headers: List[str] = []
    if not args.no_headers:
        headers = list(DEFAULT_HEADERS_MAP.values())
        if args.no_ua:
            headers = [h for h in headers if not h.lower().startswith("user-agent")]
        if args.no_xff:
            headers = [h for h in headers if not h.lower().startswith("x-forwarded-for")]
        if args.no_originating:
            headers = [h for h in headers if not h.lower().startswith("x-originating-ip")]
        if args.no_forwarded_host:
            headers = [h for h in headers if not h.lower().startswith("x-forwarded-host")]
    if args.header:
        for h in args.header:
            if ":" in h:
                headers.append(h.strip())
            else:
                print(f"[!] Ignoring malformed header (no colon found): {h}")

    # if interactive and user didn't pass header flags, ask
    passed_header_control = any([args.no_headers, args.no_ua, args.no_xff, args.no_originating, args.no_forwarded_host, bool(args.header)])
    if not args.yes and not passed_header_control:
        use_defaults = input("Use default headers? (Y/n): ").strip().lower()
        if use_defaults in ("n", "no"):
            headers = []
            print("Enter custom headers one per line (format: Name: value). Empty line when done.")
            custom_list: List[str] = []
            while True:
                try:
                    line = input().strip()
                except EOFError:
                    break
                if not line:
                    break
                if ":" not in line:
                    print("Invalid header (missing ':'). Try again.")
                    continue
                custom_list.append(line)
            headers = custom_list
            print(f"[+] Using custom headers: {headers}")
        else:
            print(f"[+] Using headers: {headers}")

    results: dict[str, dict] = {}

    def do_run_for_target(target: str):
        print(f"\n[+] Running ffuf against: {target}\n")
        cmd = build_ffuf_cmd(resolved, target, args.threads, args.depth, args.follow, headers)
        rc, output = stream_run_and_capture(cmd)
        results[target] = {"rc": rc, "output": output}

    # Run scans
    if source_mode == "domain":
        target = domain_to_target(source_value)
        do_run_for_target(target)
    elif source_mode == "domain-list":
        list_path = Path(source_value)
        if not list_path.is_file():
            print(f"Error: domain-list file not found: {list_path}", file=sys.stderr)
            return
        with list_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = line.strip()
                if not d:
                    continue
                target = domain_to_target(d)
                do_run_for_target(target)
    elif source_mode == "file":
        tgt_file = Path(source_value)
        if not tgt_file.is_file():
            print(f"Error: target file not found: {tgt_file}", file=sys.stderr)
            return
        with tgt_file.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip()
                if not t:
                    continue
                if "FUZZ" not in t:
                    t = t.rstrip("/") + "/FUZZ"
                do_run_for_target(t)
    elif source_mode == "single":
        t = source_value
        if "FUZZ" not in t:
            t = t.rstrip("/") + "/FUZZ"
        do_run_for_target(t)
    else:
        print("Unknown source mode. Exiting.", file=sys.stderr)
        return

    ask_and_save_combined(results, resolved)

# ===== Main Entrypoint =====
def main():
    print_banner()

    # If script invoked with no args -> show menu interactive
    if len(sys.argv) == 1:
        while True:
            print("=== Menu ===")
            print("1) Target")
            print("2) Instructions")
            print("3) Exit")
            sel = input("Choose [1-3]: ").strip() or "1"
            if sel == "1":
                run_scan_flow_interactive()
            elif sel == "2":
                print_instructions()
            elif sel == "3":
                print("Goodbye.")
                sys.exit(0)
            else:
                print("Invalid selection. Choose 1, 2, or 3.")
    # Otherwise parse CLI flags and run non-menu route
    parser = argparse.ArgumentParser(description="ffuf runner (menu + CLI)")
    parser.add_argument("-d", "--domain", help="Single domain (e.g. example.com). Will be used as https://<domain>/FUZZ")
    parser.add_argument("-dL", "--domain-list", dest="domain_list", help="File with domains (one per line). Each becomes https://<domain>/FUZZ")
    parser.add_argument("--target", help="Target URL (include FUZZ) or path to file with targets")
    parser.add_argument("--wordlist", help="Wordlist path (if missing will be fetched/search in seclists/)")
    parser.add_argument("--threads", type=int, help="Threads", default=100)
    parser.add_argument("--depth", type=int, help="Recursion depth", default=2)
    parser.add_argument("--follow", action="store_true", help="Follow redirects")
    parser.add_argument("--yes", action="store_true", help="Non-interactive, accept defaults / provided flags")
    parser.add_argument("--no-headers", action="store_true", help="Remove all default headers")
    parser.add_argument("--no-ua", action="store_true", help="Remove default User-Agent header")
    parser.add_argument("--no-xff", action="store_true", help="Remove default X-Forwarded-For header")
    parser.add_argument("--no-originating", action="store_true", help="Remove default X-Originating-IP header")
    parser.add_argument("--no-forwarded-host", action="store_true", help="Remove default X-Forwarded-Host header")
    parser.add_argument("-H", "--header", action="append", help="Add custom header (e.g. -H 'X-Test: 1')", default=[])
    # Accept the same flags used earlier
    args = parser.parse_args()
    # If any flags provided, run non-interactive CLI flow
    # (Note: when flags are present, skip the menu)
    run_with_args(args)

if __name__ == "__main__":
    main()
