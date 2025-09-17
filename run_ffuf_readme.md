# run_ffuf — SainiON Hacks

This repository contains two utilities that wrap **ffuf** (Fuzz Faster U Fool): a terminal/CLI script and a Tkinter GUI.

- **run_ffuf.py** — interactive CLI/script with menu, smart SecLists fetching, header controls, streaming ffuf output, and optional TXT save.
- **run_ffuf_gui.py** — Tkinter GUI wrapper that provides the same features with buttons, live output pane, and file dialogs.

---

## What's included

1. `run_ffuf.py` — CLI version
2. `run_ffuf_gui.py` — GUI version (Tkinter)
3. `README.md` (this file)
4. Optional: `seclists/` directory (if you `git clone` SecLists or let script auto-fetch)

---

## Requirements

- Python 3.8+
- `ffuf` installed and available in `PATH` (https://github.com/ffuf/ffuf)
- `git` (recommended) and/or `curl`/`wget` for automatic SecLists fetching
- For GUI: Tkinter (usually bundled with standard Python on macOS / Linux; on Windows install the standard Python distribution)

Install ffuf on Debian/Ubuntu (example):

```bash
sudo apt update && sudo apt install ffuf
# or build from source per ffuf docs
```

Install Python dependencies (none required beyond standard library). If you want fancy figlets in other scripts, `pyfiglet` can be installed with `pip install pyfiglet`.

---

## Quick usage (CLI)

Run the CLI script (menu mode):

```bash
python3 run_ffuf.py
```

Or run non-interactively with flags (examples):

```bash
# Single domain (auto builds https://<domain>/FUZZ)
python3 run_ffuf.py -d example.com

# Domain list file (one domain per line)
python3 run_ffuf.py -dL domains.txt

# Target file (full URLs or FUZZ placeholders)
python3 run_ffuf.py --target targets.txt
```

The script streams ffuf output live. After the run it asks whether to save combined results to a `.txt` file.

---

## Quick usage (GUI)

Run the GUI app:

```bash
python3 run_ffuf_gui.py
```

Features available in the GUI:

- Choose mode (Single domain / Domain list / Target file)
- Pick or auto-download wordlist (SecLists)
- Toggle default headers or add custom headers
- Set threads and recursion depth
- Start / Stop scans with live output in the text pane
- Save captured results to `.txt`

---

## Screenshots

Place your screenshots in `screenshots/` and name them as follows (these paths are referenced below):

- `screenshots/cli.png` — screenshot of the CLI script running (menu or streaming output)
- `screenshots/gui.png` — screenshot of the GUI app while scanning

To take screenshots (examples):

- Linux (using `scrot`):
  ```bash
  scrot screenshots/cli.png
  scrot screenshots/gui.png
  ```

- macOS (built-in):
  - Press `Cmd+Shift+4` and select area; files will appear on your Desktop — move them into `screenshots/` and rename.

- Windows (built-in Snipping Tool or `Win+Shift+S`):
  - Save the images and move them into `screenshots/`.

Add the images to the repo in the `screenshots/` folder and then they will appear in this README.

---

## README — with embedded images

Below are the Markdown image links you can use (they rely on the `screenshots/` folder):

```md
![CLI run_ffuf menu / streaming output](screenshots/cli.png)

![GUI run_ffuf screenshot](screenshots/gui.png)
```

When the images are present, GitHub/GitLab will render them in this README.

---

## Example saved TXT output (what the script writes)

When you choose to save combined results, the script writes a human-readable TXT with the following structure:

```
SainiON Hacks | https://www.youtube.com/@sainionhacks
Security tools & automation scripts. Subscribe for hacking tutorials and tooling.
Script: run_ffuf.py vX.X
Wordlist: seclists/Discovery/.../directory-list-2.3-big.txt
Generated: 2025-09-17T12:00:00Z

================================================================================
TARGET: https://example.com/FUZZ
Return code: 0
------------------------------------------------------------
<raw ffuf output lines...>

================================================================================
```

---

## Notes & tips

- Only scan targets you are authorized to test. Use responsibly.
- If the script cannot auto-download SecLists, clone manually once to `./seclists/`:

```bash
git clone --depth=1 https://github.com/danielmiessler/SecLists.git seclists
```

- If the GUI blocks on large scans, reduce thread count or run the CLI version in a separate terminal.

---

## Licensing & Attribution

This wrapper and README were prepared for you by SainiON Hacks. Customize the banner text at the top of the scripts.

---

## Contact / Feedback

If you want modifications (packaging with PyInstaller, automatic parsing of interesting results, concurrency options, or embedding metadata into ffuf JSON), open an issue or contact me via your preferred channel.

