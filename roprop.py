#!/usr/bin/env python3
"""
  ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████ 
  ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔═══╝
  ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝
  v4.0 — ROP Chain, Shellcode Filter & Assembler
  A tool for exploit development, research and CTF.

Usage:
  python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  python roprop.py rop.txt "\\x00\\x0a" --milk
  python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.1.77"
  python roprop.py asm "push rax" -c amd64
  python roprop.py disasm "50" -c amd64

Help:
  --help / --help-br / --help-es   short, copy-paste friendly
  --man  / --man-br  / --man-es    full manual, paged

Notes:
  * asm / disasm require pwntools (pip install pwntools). It is imported
    lazily, so every other mode keeps working without it installed.
  * asm / disasm use -c/--cpu (never -a) so nothing collides with the
    pre-existing ROP flags: -a/--address, -m, -j, -s, -t, -b.
"""

import sys
import os
import re
import argparse
import time
import struct
import platform
import shutil
import subprocess

# ─────────────────────────────────────────────────────────────
# CROSS-PLATFORM COLOR SUPPORT
# ─────────────────────────────────────────────────────────────

def _setup_colors():
    """
    Enable ANSI color codes on all platforms.
    On Windows, tries colorama first, then falls back to raw VT mode.
    Returns True if colors are supported.
    """
    if platform.system() == "Windows":
        try:
            import colorama
            colorama.init(autoreset=False)
            return True
        except ImportError:
            pass
        # Attempt to enable VT processing via ctypes (Windows 10 1511+)
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True  # Linux/macOS always support ANSI

_COLORS_ENABLED = _setup_colors()

def _c(code):
    return code if _COLORS_ENABLED else ""

# Color palette — cyberpunk/terminal aesthetic
GREEN      = _c('\033[92m')
YELLOW     = _c('\033[93m')
RED        = _c('\033[91m')
CYAN       = _c('\033[96m')
MAGENTA    = _c('\033[95m')
WHITE      = _c('\033[97m')
DIM        = _c('\033[2m')
RESET      = _c('\033[0m')
BOLD       = _c('\033[1m')
ORANGE     = _c('\033[38;5;208m')
ACID       = _c('\033[38;5;154m')   # bright lime — accent color
PINK       = _c('\033[38;5;198m')   # hot pink — warnings

# ─────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────

VERSION       = "4.0"
MAX_GADGET_INSTRUCTIONS = 5

# Sub-commands handled by the assembler front-end. Anything NOT in this tuple
# falls through to the original ROP/generator parser untouched.
ASM_COMMANDS  = ("asm", "disasm")
ARCH_CHOICES  = ["x86", "amd64", "arm", "arm64"]

# Cookbook: human-readable categories mapped to regex patterns.
# Used by --milk mode and as query shortcuts.
COOKBOOK: dict[str, list[str]] = {
    "Get ESP (Stack Pointer)": [
        r"push esp .* pop eax", r"push esp .* pop esi",
        r"mov eax, esp", r"mov ebx, esp", r"mov ecx, esp",
        r"mov edx, esp", r"mov esi, esp", r"mov edi, esp", r"mov ebp, esp",
    ],
    "Zero Out EAX": [r"xor eax, eax", r"sub eax, eax", r"and eax, 0"],
    "Zero Out EBX": [r"xor ebx, ebx", r"sub ebx, ebx", r"and ebx, 0"],
    "Zero Out ECX": [r"xor ecx, ecx", r"sub ecx, ecx", r"and ecx, 0"],
    "Zero Out EDX": [r"xor edx, edx", r"sub edx, edx", r"and edx, 0"],
    "Zero Out ESI": [r"xor esi, esi", r"sub esi, esi", r"and esi, 0"],
    "Zero Out EDI": [r"xor edi, edi", r"sub edi, edi", r"and edi, 0"],
    "Increment Register": [
        r"inc eax", r"inc ecx", r"inc edx", r"inc ebx",
        r"inc esi", r"inc edi", r"add eax, 1", r"add esi, 1",
    ],
    "Decrement Register": [r"dec eax", r"sub eax, 1", r"dec esi", r"sub esi, 1"],
    "Negate Register":    [r"neg eax", r"neg ebx", r"neg ecx", r"neg edx"],
    "Add (Offset)": [
        r"add eax, ecx", r"add eax, edx", r"add eax, ebx", r"add eax, esi",
    ],
    "Subtract (Offset)": [
        r"sub eax, ecx", r"sub eax, edx", r"sub eax, ebx", r"sub eax, esi",
    ],
    "Dereference EAX (Read Memory)": [
        r"mov eax, dword \[eax.*?\]", r"mov eax, \[eax.*?\]",
    ],
    "Dereference ESI (Read Memory)": [
        r"mov esi, dword \[esi.*?\]", r"mov esi, \[esi.*?\]",
    ],
    "Write-What-Where (Any Register)": [
        r"mov dword \[esi.*?\], eax", r"mov \[esi.*?\], eax",
        r"mov dword \[eax.*?\], ebx", r"mov \[eax.*?\], ebx",
        r"mov dword \[eax.*?\], ecx", r"mov \[eax.*?\], ecx",
        r"mov dword \[edi.*?\], eax", r"mov \[edi.*?\], eax",
        r"mov dword \[edx.*?\], eax", r"mov dword \[ebx.*?\], eax",
    ],
    "Stack Pivot": [
        r"xchg eax, esp", r"xchg esp, eax",
        r"mov esp, eax", r"mov esp, ebp", r"push eax .* pop esp",
    ],
    "JMP ESP / Trampoline": [r"jmp esp", r"call esp", r"push esp .* ret"],
    "TEB/PEB Read (FS Segment)": [r"fs:"],
}

# ─────────────────────────────────────────────────────────────
# UI / DISPLAY
# ─────────────────────────────────────────────────────────────

BANNER = f"""{CYAN}{BOLD}
  ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████╗
  ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔═══╝
  ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝{RESET}
  {DIM}v{VERSION} — ROP Chain, Shellcode Filter & Assembler  |  exploit dev & CTF{RESET}
"""

SEP = f"  {DIM}{'─' * 65}{RESET}"

# Shared footer — identical in every language so the three --help variants
# can never drift apart.
FOOTER = f"""{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{DIM}Built by {RESET}{ORANGE}{BOLD}peanut{RESET}{DIM} ~ roprop v{VERSION}{RESET}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}"""


def _flag(value: bool, on_label: str, off_label: str) -> str:
    if value:
        return f"{ACID}{BOLD}{on_label}{RESET}"
    return f"{DIM}{off_label}{RESET}"


def print_banner_rop(
    target: str,
    badchars: str,
    max_inst: int,
    show_jmps: bool,
    show_hardcoded: bool,
    allow_seh: bool,
    is_milk: bool = False,
    is_trash: bool = False,
) -> None:
    print(BANNER)
    target_display = (
        f"{PINK}{BOLD}ALL CATEGORIES  →  milk.txt{RESET}" if is_milk else target
    )
    print(SEP)
    print(f"  {WHITE}Target Query   {DIM}:{RESET}  {CYAN}{target_display}{RESET}")
    print(f"  {WHITE}Bad Characters {DIM}:{RESET}  {ORANGE}{badchars or 'none'}{RESET}")
    print(f"  {WHITE}Max Instrs     {DIM}:{RESET}  {WHITE}{max_inst}{DIM}  (ignored in trash mode){RESET}")
    print(f"  {WHITE}Trampolines    {DIM}:{RESET}  {_flag(show_jmps,  'ENABLED',  'hidden')}")
    print(f"  {WHITE}Hard Addresses {DIM}:{RESET}  {_flag(show_hardcoded, 'ENABLED', 'filtered')}")
    print(f"  {WHITE}FS / SEH       {DIM}:{RESET}  {_flag(allow_seh,  'ALLOWED',  'blocked')}")
    print(f"  {WHITE}Trash Mode     {DIM}:{RESET}  {_flag(is_trash,   'ON  (raw, no quality filter)', 'off')}")
    print(SEP + "\n")


def print_banner_generator(target: str, badchars: str) -> None:
    print(BANNER)
    print(SEP)
    print(f"  {WHITE}Mode           {DIM}:{RESET}  {PINK}{BOLD}String / Payload Generator{RESET}")
    print(f"  {WHITE}Target         {DIM}:{RESET}  {CYAN}'{target}'{RESET}")
    print(f"  {WHITE}Bad Characters {DIM}:{RESET}  {ORANGE}{badchars or 'none'}{RESET}")
    print(SEP + "\n")


def print_banner_asm(command: str, arch: str, badchars: str) -> None:
    label = "Assembler  (asm → shellcode)" if command == "asm" \
            else "Disassembler  (shellcode → asm)"
    print(BANNER)
    print(SEP)
    print(f"  {WHITE}Mode           {DIM}:{RESET}  {PINK}{BOLD}{label}{RESET}")
    print(f"  {WHITE}Architecture   {DIM}:{RESET}  {CYAN}{arch}{RESET}")
    print(f"  {WHITE}Bad Characters {DIM}:{RESET}  {ORANGE}{badchars or 'none'}{RESET}")
    print(SEP + "\n")


def show_spinner(label: str = "Scanning binary and searching for gadgets") -> None:
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    print(f"  {CYAN}{label}  {RESET}", end="", flush=True)
    end_time = time.time() + 2.0
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\b{frames[i % len(frames)]}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\b{GREEN}✔{RESET}\n\n")
    sys.stdout.flush()


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)


# ─────────────────────────────────────────────────────────────
# HELP PAGER
# ─────────────────────────────────────────────────────────────
#
# All three --help variants are long enough to overflow a normal terminal,
# so the shell naturally scrolls to the LAST screenful and the reader has
# to scroll back up to start from the top. Routing the text through a
# pager (like `git --help`, `man`, `less` itself) opens it at the top
# instead, and the reader scrolls down with arrows / space / PgDn and
# quits with 'q' — the layout everyone already knows.

def _less_supports_mouse() -> bool:
    """
    less >= 581 (2021) understands --mouse: wheel-up/wheel-down scroll the
    page like arrow keys, instead of only doing text selection. Detected
    from `less --version` so an older/BSD less on the box is never handed
    a flag it doesn't recognize.
    """
    try:
        out = subprocess.run(["less", "--version"], capture_output=True,
                              text=True, timeout=2).stdout
        match = re.search(r"less\s+(\d+)", out)
        return bool(match) and int(match.group(1)) >= 581
    except Exception:
        return False


def _pager_command() -> list[str] | None:
    """Pick a pager that understands ANSI colors, or None to just print."""
    if platform.system() == "Windows":
        return None  # 'more' on Windows mangles ANSI escape codes
    env_pager = os.environ.get("PAGER", "").strip()
    if env_pager:
        return env_pager.split()
    if shutil.which("less"):
        # -R  : render ANSI color codes instead of showing them raw
        # -F  : if the text fits on one screen, print it and exit (no pager)
        # -X  : don't clear the screen on exit — help stays readable after
        cmd = ["less", "-R", "-F", "-X"]
        if _less_supports_mouse():
            cmd.append("--mouse")   # lets the mouse wheel scroll, not just arrows
        return cmd
    return None


def _center(line: str, width: int) -> str:
    """Center a (possibly ANSI-colored) line within `width` columns."""
    visible = len(strip_ansi(line))
    pad = max(0, (width - visible) // 2)
    return " " * pad + line


def _scroll_hint() -> str:
    """
    A loud, centered banner shown ABOVE the help text, so the reader sees
    at a glance that there's more below — and that the mouse wheel works,
    not just the arrow keys.
    """
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    line  = f"{YELLOW}{BOLD}▼ ▼ ▼   SCROLL  /  ROLE   ▼ ▼ ▼{RESET}"
    sub   = f"{DIM}mouse wheel, ↑ / ↓, PgUp / PgDn  —  q to quit / sair{RESET}"
    return _center(line, width) + "\n" + _center(sub, width) + "\n"


def show_help(text: str) -> None:
    """
    Print help text, paged from the top when the terminal supports it.

    Falls back to a plain print() whenever paging isn't possible or safe:
    output is piped/redirected (not a TTY), no usable pager was found, or
    the pager itself fails to launch for any reason. The scroll hint is
    only added in the paged path — a redirected/piped copy of the help
    stays clean plain text.
    """
    if not sys.stdout.isatty():
        print(text)
        return

    cmd = _pager_command()
    if cmd is None:
        print(text)
        return

    paged_text = _scroll_hint() + text
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        proc.communicate(input=paged_text.encode("utf-8"))
    except (OSError, BrokenPipeError):
        print(text)


def print_signature() -> None:
    print(f"  {DIM}{'─' * 65}{RESET}")
    print(f"  {DIM}crafted by {RESET}{ORANGE}{BOLD}peanut{RESET}  {DIM}~ roprop v{VERSION}{RESET}")
    print()

# ─────────────────────────────────────────────────────────────
# CORE — STRING PUSH GENERATION
# ─────────────────────────────────────────────────────────────

def chunk_string(s: str, chunk_size: int) -> list[bytes]:
    encoded = s.encode("utf-8")
    pad = (chunk_size - (len(encoded) % chunk_size)) % chunk_size
    encoded += b"\x00" * pad
    return [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]


def has_bad_bytes(data: bytes, badchars: bytes) -> bool:
    return bool(badchars) and any(b in badchars for b in data)


def build_struct_fmt(chunk_size: int, endian: str) -> str:
    return (">" if endian == "big" else "<") + ("I" if chunk_size == 4 else "Q")


def generate_push_alternatives(
    chunk: bytes, chunk_size: int, endian: str, badchars: bytes
) -> list[str]:
    fmt = build_struct_fmt(chunk_size, endian)
    value_int = struct.unpack(fmt, chunk)[0]
    max_val = 1 << (chunk_size * 8)
    ptr = "dword" if chunk_size == 4 else "qword"
    suggestions: list[str] = []

    # NEG alternative (in-place via [esp])
    neg_int = (max_val - value_int) & (max_val - 1)
    neg_bytes = struct.pack(fmt, neg_int)
    if not has_bad_bytes(neg_bytes, badchars):
        suggestions.append(
            f"  {YELLOW}; Alternative — NEG in-place (no register clobbering){RESET}\n"
            f"  {GREEN}push 0x{neg_int:0{chunk_size * 2}x}{RESET}\n"
            f"  {GREEN}neg  {ptr} [esp]{RESET}"
        )

    # XOR alternative (in-place via [esp])
    for key in range(1, 256):
        key_bytes = bytes([key] * chunk_size)
        if has_bad_bytes(key_bytes, badchars):
            continue
        xor_bytes = bytes(a ^ b for a, b in zip(chunk, key_bytes))
        if not has_bad_bytes(xor_bytes, badchars):
            xor_int = struct.unpack(fmt, xor_bytes)[0]
            key_int = struct.unpack(fmt, key_bytes)[0]
            suggestions.append(
                f"  {CYAN}; Alternative — XOR in-place (no register clobbering){RESET}\n"
                f"  {GREEN}push 0x{xor_int:0{chunk_size * 2}x}{RESET}\n"
                f"  {GREEN}xor  {ptr} [esp], 0x{key_int:0{chunk_size * 2}x}{RESET}"
            )
            break

    return suggestions


def cmd_string(s: str, badchars: bytes, chunk_size: int = 4, endian: str = "little") -> None:
    chunks = chunk_string(s, chunk_size)
    print(f"  {WHITE}{BOLD}Generated Assembly (push in reverse order):{RESET}\n")

    for chunk in reversed(chunks):
        fmt = build_struct_fmt(chunk_size, endian)
        value = struct.unpack(fmt, chunk)[0]
        packed = struct.pack(fmt, value)
        readable = chunk.decode("utf-8", errors="replace").replace("\x00", "\\x00")

        if has_bad_bytes(packed, badchars):
            print(f"  {RED}; [!] Bad char in block '{readable}'  (0x{value:0{chunk_size * 2}x}){RESET}")
            alts = generate_push_alternatives(chunk, chunk_size, endian, badchars)
            if alts:
                print(alts[0])
            else:
                print(f"  {RED}; [–] No clean alternative found for this block.{RESET}")
            print()
        else:
            print(f"  {GREEN}push 0x{value:0{chunk_size * 2}x}  {DIM}; '{readable}'{RESET}")

    print(f"\n{SEP}\n")

# ─────────────────────────────────────────────────────────────
# CORE — IP PUSH GENERATION
# ─────────────────────────────────────────────────────────────

def _colorize_hex(val: int, badchars: bytes) -> str:
    h = f"{val:08x}"
    if not badchars:
        return f"0x{h}"
    result = "0x"
    for i in range(0, 8, 2):
        byte_val = int(h[i : i + 2], 16)
        if byte_val in badchars:
            result += f"{RED}{h[i:i+2]}{RESET}"
        else:
            result += h[i : i + 2]
    return result


def _colorize_bytes(data: bytes, badchars: bytes) -> str:
    parts = []
    for b in data:
        entry = hex(b)
        if badchars and b in badchars:
            parts.append(f"{RED}{entry}{RESET}")
        else:
            parts.append(entry)
    return "[" + ", ".join(parts) + "]"


def cmd_ip(ip_str: str, badchars: bytes) -> None:
    try:
        octets = ip_str.split(".")
        if len(octets) != 4:
            raise ValueError("Expected 4 octets.")
        raw = bytes(int(x) for x in octets)
        val = int.from_bytes(raw, "little")
        neg = (0x1_0000_0000 - val) & 0xFFFF_FFFF
        val_bytes = val.to_bytes(4, "little")
        neg_bytes = neg.to_bytes(4, "little")

        print(f"  {WHITE}{BOLD}IP Calculation Results:{RESET}")
        print(f"    {DIM}IP Address   :{RESET}  {CYAN}{ip_str}{RESET}")
        print(f"    {DIM}Normal hex   :{RESET}  {_colorize_hex(val, badchars)}"
              f"  {DIM}→  {_colorize_bytes(val_bytes, badchars)}{RESET}")
        print(f"    {DIM}NEG hex      :{RESET}  {_colorize_hex(neg, badchars)}"
              f"  {DIM}→  {_colorize_bytes(neg_bytes, badchars)}{RESET}")
        print()
        print(f"  {WHITE}{BOLD}Generated Assembly:{RESET}\n")

        if has_bad_bytes(val_bytes, badchars):
            print(f"  {RED}; [!] Bad char detected in normal hex  (0x{val:08x}){RESET}")
            if not has_bad_bytes(neg_bytes, badchars):
                print(f"  {YELLOW}; Safe alternative — NEG in-place{RESET}")
                print(f"  {GREEN}push 0x{neg:08x}{RESET}")
                print(f"  {GREEN}neg  dword [esp]{RESET}")
            else:
                print(f"  {RED}; [–] NEG alternative (0x{neg:08x}) also contains bad chars!{RESET}")
                print(f"  {YELLOW}; Consider XOR or dynamic addition to construct this IP.{RESET}")
        else:
            print(f"  {GREEN}push 0x{val:08x}  {DIM}; IP '{ip_str}'{RESET}")

        print(f"\n{SEP}\n")
    except Exception as exc:
        print(f"  {RED}[!] Error processing IP: {exc}{RESET}")

# ─────────────────────────────────────────────────────────────
# CORE — ROP GADGET ANALYSIS
# ─────────────────────────────────────────────────────────────

def parse_badchars(raw: str) -> bytes:
    if not raw:
        return b""
    cleaned = raw.replace("'", "").replace('"', "")
    return cleaned.encode().decode("unicode_escape").encode("latin-1")


def address_has_bad_bytes(addr_hex: str, badchars: bytes) -> bool:
    addr_hex = addr_hex.zfill(8)
    return any(int(addr_hex[i : i + 2], 16) in badchars for i in range(0, 8, 2))


def detect_clobbered_registers(instructions: list[str]) -> list[str]:
    """Return list of registers visibly modified (written to) by the gadget."""
    REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    clobbered: set[str] = set()
    for ins in instructions:
        ins_low = ins.lower()
        if "pop" in ins_low:
            for r in REGS:
                if r in ins_low:
                    clobbered.add(r)
        elif any(op in ins_low for op in ("mov", "add", "sub", "xor", "inc", "dec", "and", "or", "lea")):
            dest = ins_low.split(",")[0]
            if "[" not in dest:
                for r in REGS:
                    if r in dest:
                        clobbered.add(r)
    return sorted(clobbered)


def calculate_stack_delta(instructions: list[str]) -> tuple[int, int, int, int]:
    """
    Returns (pop_count, retn_dword_count, total_padding_dwords, remainder_bytes).
    """
    pops   = 0
    pushes = 0
    retn_offset = 0

    for ins in instructions:
        low = ins.strip().lower()
        if low.startswith("push ") or low in ("pushad", "pushfd"):
            pushes += 8 if low == "pushad" else 1
        elif low.startswith("pop ") or low in ("popad", "popfd"):
            if low == "popad":
                if pushes >= 8:
                    pushes -= 8
                else:
                    pops   += 8 - pushes
                    pushes  = 0
            else:
                if pushes > 0:
                    pushes -= 1
                else:
                    pops += 1
        elif "ret" in low and len(low.split()) > 1:
            try:
                retn_offset = int(low.split()[1], 16)
            except ValueError:
                pass

    retn_dwords  = retn_offset // 4
    remainder    = retn_offset % 4
    total        = pops + retn_dwords
    return pops, retn_dwords, total, remainder


def format_gadget(r: dict, no_color: bool = False) -> str:
    """Render a single gadget result as a nicely formatted string."""
    g  = lambda c: "" if no_color else c
    W  = g(WHITE);  Y = g(YELLOW); R = g(RED)
    Pk = g(PINK);   C = g(CYAN);   Gr = g(GREEN)
    D  = g(DIM);    Rs = g(RESET); B = g(BOLD)

    lines: list[str] = []
    lines.append(f"  {D}┌─{Rs} {W}{B}{r['addr']}{Rs}  {D}│{Rs}  {r['instrs']}")

    if r["clobbered"]:
        regs = ", ".join(r["clobbered"]).upper()
        lines.append(f"  {D}│  {Y}▲  Clobbered: {regs}{Rs}")

    if r["ret_pad"] > 0:
        lines.append(
            f"  {D}│  {R}⚠  RETN detected — requires {r['ret_pad']} extra DWORD(s) on stack{Rs}"
        )

    if r["remainder"] > 0:
        lines.append(
            f"  {D}│  {Pk}{B}✖  Stack misalignment: {r['remainder']} byte(s) remainder!{Rs}"
        )
    elif r["is_jmp"]:
        lines.append(f"  {D}│  {C}→  Gadget ends with JMP/CALL{Rs}")

    # Python rop chain line
    lines.append(f"  {D}│{Rs}")
    lines.append(f"  {D}│  {Gr}rop += pack('<L', {r['addr']})  # {r['instrs']}{Rs}")

    # Padding lines
    pad = r["total_pad"]
    if pad > 0:
        if pad > 8:
            lines.append(
                f"  {D}│  {Gr}rop += pack('<L', 0x50505050) {R}* {pad}{Gr}  # padding (large!){Rs}"
            )
        elif pad == 1:
            lines.append(
                f"  {D}│  {Gr}rop += pack('<L', 0x50505050)       # padding{Rs}"
            )
        else:
            lines.append(
                f"  {D}│  {Gr}rop += pack('<L', 0x50505050) {R}* {pad}{Gr}  # padding{Rs}"
            )

    if r["remainder"] > 0:
        lines.append(
            f"  {D}│  {Pk}rop += b'A' {R}* {r['remainder']}{Pk}  # realign stack after RETN{Rs}"
        )

    lines.append(f"  {D}└{'─' * 60}{Rs}\n")
    return "\n".join(lines)


def search_gadgets(
    lines: list[str],
    badchars: bytes,
    pattern: str,
    show_jmps: bool,
    show_hardcoded: bool,
    allow_seh: bool,
    trash_mode: bool = False,
) -> list[dict]:
    results: list[dict] = []

    for line in lines:
        clean = line.split("(")[0].strip()
        if not clean.startswith("0x") or ":" not in clean:
            continue

        addr_raw, instrs = clean.split(":", 1)
        addr_hex = addr_raw.strip()[2:]

        if address_has_bad_bytes(addr_hex, badchars):
            continue

        if not re.search(pattern, instrs.lower(), re.IGNORECASE):
            continue

        if not trash_mode:
            if "call " in instrs.lower() and not show_jmps:
                continue
            if not allow_seh and "fs:" in instrs.lower():
                continue
            if not show_hardcoded:
                # strip known zero-address patterns before testing
                test_instrs = instrs.replace("0x00000000", "")
                if re.search(r"0x[0-9a-fA-F]{8}", test_instrs):
                    continue

        parts = [i.strip() for i in instrs.split(";") if i.strip()]
        if not parts:
            continue
        if not trash_mode and len(parts) > MAX_GADGET_INSTRUCTIONS:
            continue

        last = parts[-1].lower()
        is_ret      = "ret"  in last
        is_jmp_call = "jmp"  in last or "call" in last

        if trash_mode:
            if not is_ret:
                continue
        else:
            if not is_ret:
                if not (is_jmp_call and show_jmps):
                    continue

        clobbered            = detect_clobbered_registers(parts)
        pops, ret_p, total, rem = calculate_stack_delta(parts)

        results.append({
            "addr":      addr_raw.strip(),
            "instrs":    instrs.strip(),
            "clobbered": clobbered,
            "pops":      pops,
            "ret_pad":   ret_p,
            "total_pad": total,
            "remainder": rem,
            "length":    len(parts),
            "is_jmp":    is_jmp_call,
        })

    # Best gadgets first: fewest stack side-effects, then fewest instructions
    results.sort(key=lambda x: (x["total_pad"], x["length"]))
    return results

# ─────────────────────────────────────────────────────────────
# CORE — ASSEMBLER / DISASSEMBLER  (pwntools-powered)
# ─────────────────────────────────────────────────────────────

def _load_pwntools():
    """
    Import pwntools on demand and return (asm_module, context).

    Lazy on purpose: the ROP finder and the string/IP generators must keep
    working on a box without pwntools, and `import pwn` costs a second or
    two of start-up we do not want to pay on every gadget search.
    """
    try:
        from pwnlib import asm as _asm_mod
        from pwnlib.context import context as _context
    except ImportError:
        print(f"\n  {RED}[!] pwntools is required for asm / disasm mode.{RESET}")
        print(f"  {YELLOW}    pip install pwntools{RESET}")
        print(f"  {DIM}    (every other roprop mode works without it){RESET}\n")
        sys.exit(1)
    _context.log_level = "error"      # keep pwnlib's own logging out of the way
    return _asm_mod, _context


def parse_shellcode_hex(raw: str) -> bytes:
    """
    Accept shellcode in any of the shapes people actually paste:
        5058        50 58        50,58
        \\x50\\x58    0x50 0x58    "\\x50\\x58"
    """
    cleaned = raw.strip().replace("'", "").replace('"', "")
    cleaned = cleaned.replace("\\x", "").replace("\\X", "")
    cleaned = re.sub(r"0[xX]", "", cleaned)
    cleaned = re.sub(r"[\s,;:_\-]", "", cleaned)

    if not cleaned:
        raise ValueError("empty shellcode")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        bad = sorted({c for c in cleaned if c not in "0123456789abcdefABCDEF"})
        raise ValueError(f"not hexadecimal — unexpected character(s): {' '.join(bad)}")
    if len(cleaned) % 2:
        raise ValueError(f"odd number of hex digits ({len(cleaned)}) — incomplete byte")
    return bytes.fromhex(cleaned)


def _apply_context(context, arch: str) -> None:
    context.clear()
    context.arch      = arch
    context.os        = "linux"
    context.log_level = "error"


def assemble(code: str, arch: str) -> bytes:
    """Assemble source into raw shellcode bytes."""
    asm_mod, context = _load_pwntools()
    _apply_context(context, arch)
    try:
        return asm_mod.asm(code)
    except Exception as exc:
        raise ValueError(f"assembly failed — {exc}")


def disassemble(raw_bytes: bytes, arch: str) -> str:
    """Disassemble raw shellcode bytes into readable assembly."""
    asm_mod, context = _load_pwntools()
    _apply_context(context, arch)
    try:
        return asm_mod.disasm(raw_bytes)
    except Exception as exc:
        raise ValueError(f"disassembly failed — {exc}")


def _hilite_hex(data: bytes, badchars: bytes) -> str:
    out = []
    for b in data:
        cell = f"{b:02x}"
        out.append(f"{RED}{BOLD}{cell}{RESET}{GREEN}" if badchars and b in badchars else cell)
    return "".join(out)


def _hilite_escaped(data: bytes, badchars: bytes) -> str:
    out = []
    for b in data:
        cell = f"\\x{b:02x}"
        out.append(f"{RED}{BOLD}{cell}{RESET}{GREEN}" if badchars and b in badchars else cell)
    return "".join(out)


def _badchar_verdict(data: bytes, badchars: bytes) -> None:
    if not badchars:
        return
    hits = sorted({b for b in data if b in badchars})
    if hits:
        listed = " ".join(f"\\x{b:02x}" for b in hits)
        print(f"  {RED}{BOLD}✖  Bad char(s) present in shellcode: {listed}{RESET}")
        print(f"  {DIM}   Rewrite the instruction(s) or encode the payload.{RESET}")
    else:
        print(f"  {ACID}{BOLD}✔  Clean — no bad characters in output.{RESET}")
    print()


def format_asm_output(code: str, shellcode: bytes, arch: str, badchars: bytes) -> None:
    escaped = "".join(f"\\x{b:02x}" for b in shellcode)

    print(f"  {WHITE}{BOLD}Source:{RESET}")
    for line in [l.strip() for l in code.replace(";", "\n").splitlines() if l.strip()]:
        print(f"    {CYAN}{line}{RESET}")
    print()
    print(f"  {WHITE}Architecture   {DIM}:{RESET}  {YELLOW}{arch}{RESET}")
    print(f"  {WHITE}Length         {DIM}:{RESET}  {GREEN}{len(shellcode)} byte(s){RESET}")
    print()
    print(f"  {WHITE}{BOLD}Hex:{RESET}")
    print(f"    {GREEN}{_hilite_hex(shellcode, badchars)}{RESET}")
    print()
    print(f"  {WHITE}{BOLD}Escaped:{RESET}")
    print(f"    {GREEN}{_hilite_escaped(shellcode, badchars)}{RESET}")
    print()
    print(f"  {WHITE}{BOLD}Python:{RESET}")
    print(f'    {GREEN}shellcode = b"{escaped}"{RESET}')
    print()
    _badchar_verdict(shellcode, badchars)


def format_disasm_output(raw_bytes: bytes, asm_text: str, arch: str, badchars: bytes) -> None:
    print(f"  {WHITE}{BOLD}Shellcode:{RESET}")
    print(f"    {GREEN}{_hilite_escaped(raw_bytes, badchars)}{RESET}")
    print()
    print(f"  {WHITE}Architecture   {DIM}:{RESET}  {YELLOW}{arch}{RESET}")
    print(f"  {WHITE}Length         {DIM}:{RESET}  {GREEN}{len(raw_bytes)} byte(s){RESET}")
    print()
    print(f"  {WHITE}{BOLD}Disassembly:{RESET}\n")
    for line in asm_text.rstrip().splitlines():
        if line.strip():
            print(f"    {CYAN}{line}{RESET}")
    print()
    _badchar_verdict(raw_bytes, badchars)

# ─────────────────────────────────────────────────────────────
# SHORT HELP  (--help / --help-br / --help-es)
# ─────────────────────────────────────────────────────────────
#
# Deliberately terse and NOT paged: it has to fit on one screen so the
# reader can see everything at once and copy a command straight out of
# the terminal. The long-form reference lives behind --man.

def print_help_english() -> None:
    print(f"""
{CYAN}{BOLD}roprop v{VERSION}{RESET}{DIM} — ROP chain, shellcode filter & assembler{RESET}

{YELLOW}{BOLD}USAGE{RESET}
  {WHITE}roprop.py <file> <badchars> <query>{RESET}     {DIM}search gadgets{RESET}
  {WHITE}roprop.py <file> <badchars> --milk{RESET}      {DIM}export cheat sheet to milk.txt{RESET}
  {WHITE}roprop.py -b <badchars> --string <str>{RESET}  {DIM}PUSH assembly for a string{RESET}
  {WHITE}roprop.py -b <badchars> --ip-hex <ip>{RESET}   {DIM}PUSH assembly for an IPv4{RESET}
  {WHITE}roprop.py asm <code> -c <arch>{RESET}          {DIM}assemble    → shellcode{RESET}
  {WHITE}roprop.py disasm <hex> -c <arch>{RESET}        {DIM}disassemble → assembly{RESET}

{YELLOW}{BOLD}FLAGS{RESET}
  {CYAN}ROP search{RESET}  -m --milk  -j --jmps  -a --address  -s --seh  -t --trash
  {CYAN}Generator{RESET}   -b --badchars-opt  --string  --ip-hex  --size {{4,8}}  --endian {{little,big}}
  {CYAN}Assembler{RESET}   -c --cpu {{x86,amd64,arm,arm64}}  -b --badchars-opt

{YELLOW}{BOLD}COPY & PASTE{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
  {GREEN}python3 roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
  {GREEN}python3 roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
  {GREEN}python3 roprop.py asm "push rax; pop rbx" -c amd64{RESET}
  {GREEN}python3 roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}

{YELLOW}{BOLD}MORE{RESET}
  {WHITE}--man{RESET}   full manual, paged   {DIM}· --man-br (pt) · --man-es (es){RESET}
  {DIM}short help in other languages: --help-br · --help-es{RESET}
""")
    sys.exit(0)


def print_help_portuguese() -> None:
    print(f"""
{CYAN}{BOLD}roprop v{VERSION}{RESET}{DIM} — filtro de ROP chain, shellcode e assembler{RESET}

{YELLOW}{BOLD}USO{RESET}
  {WHITE}roprop.py <arquivo> <badchars> <query>{RESET}  {DIM}buscar gadgets{RESET}
  {WHITE}roprop.py <arquivo> <badchars> --milk{RESET}   {DIM}exportar cheat sheet p/ milk.txt{RESET}
  {WHITE}roprop.py -b <badchars> --string <str>{RESET}  {DIM}assembly PUSH de uma string{RESET}
  {WHITE}roprop.py -b <badchars> --ip-hex <ip>{RESET}   {DIM}assembly PUSH de um IPv4{RESET}
  {WHITE}roprop.py asm <código> -c <arch>{RESET}        {DIM}montar     → shellcode{RESET}
  {WHITE}roprop.py disasm <hex> -c <arch>{RESET}        {DIM}desmontar  → assembly{RESET}

{YELLOW}{BOLD}FLAGS{RESET}
  {CYAN}Busca ROP{RESET}   -m --milk  -j --jmps  -a --address  -s --seh  -t --trash
  {CYAN}Gerador{RESET}     -b --badchars-opt  --string  --ip-hex  --size {{4,8}}  --endian {{little,big}}
  {CYAN}Assembler{RESET}   -c --cpu {{x86,amd64,arm,arm64}}  -b --badchars-opt

{YELLOW}{BOLD}COPIAR E COLAR{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
  {GREEN}python3 roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
  {GREEN}python3 roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
  {GREEN}python3 roprop.py asm "push rax; pop rbx" -c amd64{RESET}
  {GREEN}python3 roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}

{YELLOW}{BOLD}MAIS{RESET}
  {WHITE}--man-br{RESET}  manual completo em português (paginado)
  {DIM}ajuda curta em outros idiomas: --help · --help-es{RESET}
""")
    sys.exit(0)


def print_help_spanish() -> None:
    print(f"""
{CYAN}{BOLD}roprop v{VERSION}{RESET}{DIM} — filtro de cadenas ROP, shellcode y ensamblador{RESET}

{YELLOW}{BOLD}USO{RESET}
  {WHITE}roprop.py <archivo> <badchars> <query>{RESET}  {DIM}buscar gadgets{RESET}
  {WHITE}roprop.py <archivo> <badchars> --milk{RESET}   {DIM}exportar cheat sheet a milk.txt{RESET}
  {WHITE}roprop.py -b <badchars> --string <str>{RESET}  {DIM}assembly PUSH de una cadena{RESET}
  {WHITE}roprop.py -b <badchars> --ip-hex <ip>{RESET}   {DIM}assembly PUSH de una IPv4{RESET}
  {WHITE}roprop.py asm <código> -c <arch>{RESET}        {DIM}ensamblar     → shellcode{RESET}
  {WHITE}roprop.py disasm <hex> -c <arch>{RESET}        {DIM}desensamblar  → assembly{RESET}

{YELLOW}{BOLD}FLAGS{RESET}
  {CYAN}Búsqueda ROP{RESET} -m --milk  -j --jmps  -a --address  -s --seh  -t --trash
  {CYAN}Generador{RESET}    -b --badchars-opt  --string  --ip-hex  --size {{4,8}}  --endian {{little,big}}
  {CYAN}Ensamblador{RESET}  -c --cpu {{x86,amd64,arm,arm64}}  -b --badchars-opt

{YELLOW}{BOLD}COPIAR Y PEGAR{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
  {GREEN}python3 roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
  {GREEN}python3 roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
  {GREEN}python3 roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
  {GREEN}python3 roprop.py asm "push rax; pop rbx" -c amd64{RESET}
  {GREEN}python3 roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}

{YELLOW}{BOLD}MÁS{RESET}
  {WHITE}--man-es{RESET}  manual completo en español (paginado)
  {DIM}ayuda corta en otros idiomas: --help · --help-br{RESET}
""")
    sys.exit(0)


def print_help_asm() -> None:
    """Short help for `roprop.py asm|disasm --help`."""
    print(f"""
{CYAN}{BOLD}roprop v{VERSION}{RESET}{DIM} — assembler / disassembler (pwntools){RESET}

{YELLOW}{BOLD}USAGE{RESET}
  {WHITE}roprop.py asm <code> [-c ARCH] [-b BADCHARS]{RESET}
  {WHITE}roprop.py disasm <hex> [-c ARCH] [-b BADCHARS]{RESET}

{YELLOW}{BOLD}FLAGS{RESET}
  {CYAN}-c, --cpu{RESET}            {{x86, amd64, arm, arm64}}   {DIM}(default: amd64){RESET}
  {CYAN}-b, --badchars-opt{RESET}   {DIM}flag bad chars in the produced shellcode{RESET}

{YELLOW}{BOLD}HEX INPUT ACCEPTED BY disasm{RESET}
  {DIM}5058  ·  50 58  ·  50,58  ·  \\x50\\x58  ·  0x50 0x58{RESET}

{YELLOW}{BOLD}COPY & PASTE{RESET}
  {GREEN}python3 roprop.py asm "push rax; pop rbx" -c amd64{RESET}
  {GREEN}python3 roprop.py asm "xor eax, eax" -c x86 -b "\\x00\\x0a"{RESET}
  {GREEN}python3 roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}
  {GREEN}python3 roprop.py disasm "50" -c amd64{RESET}

{YELLOW}{BOLD}MORE{RESET}
  {WHITE}--man{RESET}   full manual, paged   {DIM}· --man-br (pt) · --man-es (es){RESET}
""")
    sys.exit(0)

# ─────────────────────────────────────────────────────────────
# FULL MANUAL  (--man / --man-br / --man-es)
# ─────────────────────────────────────────────────────────────

def print_man_english() -> None:
    """Print the full English manual (paged) and exit."""
    man_text = f"""{BANNER}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}ROPROP v{VERSION} — ROP Chain & Shellcode Filter{RESET}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}

{CYAN}{BOLD}QUICK START:{RESET}
  • {CYAN}ROP Search   {RESET}: python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  • {CYAN}Milk Export  {RESET}: python roprop.py rop.txt "\\x00\\x0a" --milk
  • {CYAN}String Gen   {RESET}: python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  • {CYAN}IP Generator {RESET}: python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.1.77"
  • {CYAN}Assemble     {RESET}: python roprop.py asm "push rax" -c amd64
  • {CYAN}Disassemble  {RESET}: python roprop.py disasm "50" -c amd64

{YELLOW}{BOLD}POSITIONAL ARGUMENTS:{RESET}
  {PINK}file          {RESET} Gadget file produced by rp++ or ROPgadget
  {PINK}badchars      {RESET} Bad characters to exclude (format: \\x00\\x0a)
  {PINK}query         {RESET} Instruction pattern or Cookbook shortcut

{YELLOW}{BOLD}ROP SEARCH OPTIONS:{RESET}
  {CYAN}-m, --milk       {RESET} Export ALL Cookbook categories to milk.txt
  {CYAN}-j, --jmps       {RESET} Include gadgets ending in JMP/CALL (trampolines)
  {CYAN}-a, --address    {RESET} Include gadgets with hardcoded addresses (0x41414141)
  {CYAN}-s, --seh        {RESET} Include gadgets touching FS (TEB/PEB/SEH)
  {CYAN}-t, --trash      {RESET} Unfiltered mode — drops the instruction-count limit

{YELLOW}{BOLD}GENERATOR OPTIONS (String / IP):{RESET}
  {CYAN}-b, --badchars-opt {RESET} Bad characters (use with --string/--ip-hex)
  {CYAN}--string STR      {RESET} Generate PUSH instructions for a string
  {CYAN}--ip-hex IP       {RESET} Generate PUSH instructions for an IPv4 address
  {CYAN}--size {{4,8}}       {RESET} Register size: 4 (x86) or 8 (x64)
  {CYAN}--endian {{little,big}} {RESET} Byte order (default: little)

{YELLOW}{BOLD}ASSEMBLER / DISASSEMBLER (requires pwntools):{RESET}
  {PINK}asm CODE      {RESET} Assemble source  → shellcode
  {PINK}disasm HEX    {RESET} Disassemble hex  → assembly
  {CYAN}-c, --cpu ARCH   {RESET} Architecture: x86, amd64, arm, arm64 (default: amd64)
  {CYAN}-b, --badchars-opt{RESET} Flag bad chars in the produced shellcode
  {DIM}Uses -c (never -a) so it cannot collide with -a/--address of the ROP search.{RESET}
  {DIM}pwntools is imported only in this mode — all other modes run without it.{RESET}

{YELLOW}{BOLD}HELP & MANUAL:{RESET}
  {CYAN}-h, --help       {RESET} Short help, made to copy and paste (English)
  {CYAN}--help-br        {RESET} Short help in Portuguese
  {CYAN}--help-es        {RESET} Short help in Spanish
  {CYAN}--man            {RESET} Full manual in English (this one)
  {CYAN}--man-br         {RESET} Full manual in Portuguese
  {CYAN}--man-es         {RESET} Full manual in Spanish

{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}DETAILED EXAMPLES{RESET}

{CYAN}{BOLD}1. Basic ROP Search (find gadgets by instruction){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
   Searches for gadgets containing 'pop eax', excluding null bytes and newlines

{CYAN}{BOLD}2. Using Cookbook Categories (pre-built patterns){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
   Uses built-in patterns for register zeroing (xor eax, eax | sub eax, eax)

{CYAN}{BOLD}3. Generate Complete ROP Cheat Sheet{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
   Exports ALL Cookbook categories to milk.txt (organized by category)

{CYAN}{BOLD}4. Include Trampoline Gadgets (JMP ESP, etc){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "jmp esp" --jmps{RESET}
   Default: hides JMP/CALL | With --jmps: includes them in results

{CYAN}{BOLD}5. Unfiltered Search Mode (Trash Mode){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "mov" --trash{RESET}
   Ignores MAX_GADGET_INSTRUCTIONS limit, shows ALL matches (raw/unfiltered)

{CYAN}{BOLD}6. Generate String Payload Assembly{RESET}
   {GREEN}$ python roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
   Generates PUSH instructions for "cmd.exe", avoiding bad chars

{CYAN}{BOLD}7. Generate IP Address Assembly (with NEG bypass){RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
   Generates both normal and NEG-negated forms for IPv4 addresses

{CYAN}{BOLD}8. Combine Multiple Filters{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "xchg eax, esp" --address --seh --jmps{RESET}
   Search with: hardcoded addresses ALLOWED + FS segment ALLOWED + trampolines ALLOWED

{CYAN}{BOLD}9. Generate 64-bit Payloads{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --string "test" --size 8{RESET}
   Switches to 64-bit (qword) PUSH instructions

{CYAN}{BOLD}10. Big-Endian Byte Order{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77" --endian big{RESET}
   Useful for non-x86 architectures

{CYAN}{BOLD}11. Assemble Source into Shellcode (asm){RESET}
   {GREEN}$ python roprop.py asm "push rax; pop rbx" -c amd64{RESET}
   Emits hex, \\x-escaped and ready-to-paste Python forms

{CYAN}{BOLD}12. Disassemble Shellcode (disasm){RESET}
   {GREEN}$ python roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}
   Accepts 31c0, "\\x31\\xc0", 0x31 0xc0 or "31 c0" — all work

{CYAN}{BOLD}13. Assemble with Bad-Char Verification{RESET}
   {GREEN}$ python roprop.py asm "xor eax, eax" -c x86 -b "\\x00\\x0a"{RESET}
   Assembles and flags any bad char found in the resulting shellcode

{FOOTER}
"""
    show_help(man_text)
    sys.exit(0)


def print_man_portuguese() -> None:
    """Print the full Portuguese manual (paged) and exit."""
    help_text = f"""{BANNER}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}ROPROP v{VERSION} — Filtro de ROP Chain & Shellcode{RESET}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}

{CYAN}{BOLD}COMEÇAR RÁPIDO:{RESET}
  • {CYAN}Busca ROP    {RESET}: python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  • {CYAN}Exportar Milk{RESET}: python roprop.py rop.txt "\\x00\\x0a" --milk
  • {CYAN}Gerar String {RESET}: python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  • {CYAN}Gerar IP     {RESET}: python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.1.77"
  • {CYAN}Montar ASM   {RESET}: python roprop.py asm "push rax" -c amd64
  • {CYAN}Desmontar    {RESET}: python roprop.py disasm "50" -c amd64

{YELLOW}{BOLD}ARGUMENTOS POSICIONAIS:{RESET}
  {PINK}arquivo       {RESET} Arquivo de gadgets do rp++ ou ROPgadget
  {PINK}badchars      {RESET} Caracteres ruins a excluir (formato: \\x00\\x0a)
  {PINK}query         {RESET} Padrão de instrução ou atalho Cookbook

{YELLOW}{BOLD}OPÇÕES DE BUSCA ROP:{RESET}
  {CYAN}-m, --milk       {RESET} Exportar TODAS as categorias Cookbook para milk.txt
  {CYAN}-j, --jmps       {RESET} Incluir gadgets com JMP/CALL (trampolins)
  {CYAN}-a, --address    {RESET} Incluir gadgets com endereços codificados (0x41414141)
  {CYAN}-s, --seh        {RESET} Incluir gadgets que acessam FS (TEB/PEB/SEH)
  {CYAN}-t, --trash      {RESET} Modo sem filtros — desabilita limite de instruções

{YELLOW}{BOLD}OPÇÕES DE GERADOR (String / IP):{RESET}
  {CYAN}-b, --badchars-opt {RESET} Caracteres ruins (use com --string/--ip-hex)
  {CYAN}--string STR      {RESET} Gerar instruções PUSH para string
  {CYAN}--ip-hex IP       {RESET} Gerar instruções PUSH para endereço IPv4
  {CYAN}--size {{4,8}}       {RESET} Tamanho de registrador: 4 (x86) ou 8 (x64)
  {CYAN}--endian {{little,big}} {RESET} Ordem de bytes (padrão: little)

{YELLOW}{BOLD}ASSEMBLER / DISASSEMBLER (requer pwntools):{RESET}
  {PINK}asm CÓDIGO    {RESET} Monta assembly → shellcode
  {PINK}disasm HEX    {RESET} Desmonta shellcode → assembly
  {CYAN}-c, --cpu ARCH   {RESET} Arquitetura: x86, amd64, arm, arm64 (padrão: amd64)
  {CYAN}-b, --badchars-opt{RESET} Marca em vermelho os bad chars no shellcode gerado
  {DIM}Usa -c (nunca -a) para não colidir com -a/--address da busca ROP.{RESET}
  {DIM}O pwntools só é carregado neste modo — os demais modos não dependem dele.{RESET}

{YELLOW}{BOLD}AJUDA E MANUAL:{RESET}
  {CYAN}-h, --help       {RESET} Ajuda curta, feita para copiar e colar (inglês)
  {CYAN}--help-br        {RESET} Ajuda curta em português
  {CYAN}--help-es        {RESET} Ajuda curta em espanhol
  {CYAN}--man            {RESET} Manual completo em inglês (paginado)
  {CYAN}--man-br         {RESET} Manual completo em português (este)
  {CYAN}--man-es         {RESET} Manual completo em espanhol

{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}EXEMPLOS DETALHADOS{RESET}

{CYAN}{BOLD}1. Busca básica de ROP (encontrar gadgets por instrução){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
   Busca por gadgets contendo 'pop eax', excluindo null bytes e newlines

{CYAN}{BOLD}2. Usando Categorias Cookbook (padrões pré-built){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
   Usa padrões built-in para zerar registrador (xor eax, eax | sub eax, eax)

{CYAN}{BOLD}3. Gerar Cheat Sheet ROP Completo{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
   Exporta TODAS as categorias Cookbook para milk.txt (organizado por categoria)

{CYAN}{BOLD}4. Incluir Gadgets Trampolim (JMP ESP, etc){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "jmp esp" --jmps{RESET}
   Padrão: oculta JMP/CALL | Com --jmps: inclui nos resultados

{CYAN}{BOLD}5. Modo Busca Sem Filtros (Trash Mode){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "mov" --trash{RESET}
   Ignora limite MAX_GADGET_INSTRUCTIONS, mostra TODOS os matches (bruto/sem filtro)

{CYAN}{BOLD}6. Gerar Payload de String{RESET}
   {GREEN}$ python roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
   Gera instruções PUSH para "cmd.exe", evitando caracteres ruins

{CYAN}{BOLD}7. Gerar Endereço IP (com bypass NEG){RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
   Gera forma normal e NEG-negada para endereços IPv4

{CYAN}{BOLD}8. Combinar Múltiplos Filtros{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "xchg eax, esp" --address --seh --jmps{RESET}
   Busca com: endereços PERMITIDOS + FS segment PERMITIDO + trampolins PERMITIDOS

{CYAN}{BOLD}9. Gerar Payloads 64-bit{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --string "test" --size 8{RESET}
   Muda para instruções PUSH 64-bit (qword)

{CYAN}{BOLD}10. Ordem de Bytes Big-Endian{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77" --endian big{RESET}
   Útil para arquiteturas não-x86

{CYAN}{BOLD}11. Montar Assembly (asm){RESET}
   {GREEN}$ python roprop.py asm "push rax; pop rbx" -c amd64{RESET}
   Converte as instruções em shellcode (hex, escapado e pronto p/ Python)

{CYAN}{BOLD}12. Desmontar Shellcode (disasm){RESET}
   {GREEN}$ python roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}
   Aceita 31c0, "\\x31\\xc0", 0x31 0xc0 ou "31 c0" — tudo funciona

{CYAN}{BOLD}13. Montar Checando Bad Chars{RESET}
   {GREEN}$ python roprop.py asm "xor eax, eax" -c x86 -b "\\x00\\x0a"{RESET}
   Monta e destaca em vermelho qualquer bad char presente no shellcode

{FOOTER}
"""
    show_help(help_text)
    sys.exit(0)


def print_man_spanish() -> None:
    """Print the full Spanish manual (paged) and exit."""
    help_text = f"""{BANNER}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}ROPROP v{VERSION} — Filtro de Cadenas ROP & Shellcode{RESET}
{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}

{CYAN}{BOLD}INICIO RÁPIDO:{RESET}
  • {CYAN}Búsqueda ROP  {RESET}: python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  • {CYAN}Exportar Milk {RESET}: python roprop.py rop.txt "\\x00\\x0a" --milk
  • {CYAN}Generar String{RESET}: python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  • {CYAN}Generar IP    {RESET}: python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.1.77"
  • {CYAN}Ensamblar     {RESET}: python roprop.py asm "push rax" -c amd64
  • {CYAN}Desensamblar  {RESET}: python roprop.py disasm "50" -c amd64

{YELLOW}{BOLD}ARGUMENTOS POSICIONALES:{RESET}
  {PINK}archivo       {RESET} Archivo de gadgets de rp++ o ROPgadget
  {PINK}badchars      {RESET} Caracteres malos a excluir (formato: \\x00\\x0a)
  {PINK}query         {RESET} Patrón de instrucción o atajo Cookbook

{YELLOW}{BOLD}OPCIONES DE BÚSQUEDA ROP:{RESET}
  {CYAN}-m, --milk       {RESET} Exportar TODAS las categorías Cookbook a milk.txt
  {CYAN}-j, --jmps       {RESET} Incluir gadgets con JMP/CALL (trampolines)
  {CYAN}-a, --address    {RESET} Incluir gadgets con direcciones codificadas (0x41414141)
  {CYAN}-s, --seh        {RESET} Incluir gadgets que accesan FS (TEB/PEB/SEH)
  {CYAN}-t, --trash      {RESET} Modo sin filtros — deshabilita límite de instrucciones

{YELLOW}{BOLD}OPCIONES DE GENERADOR (String / IP):{RESET}
  {CYAN}-b, --badchars-opt {RESET} Caracteres malos (use con --string/--ip-hex)
  {CYAN}--string STR      {RESET} Generar instrucciones PUSH para string
  {CYAN}--ip-hex IP       {RESET} Generar instrucciones PUSH para dirección IPv4
  {CYAN}--size {{4,8}}       {RESET} Tamaño de registro: 4 (x86) u 8 (x64)
  {CYAN}--endian {{little,big}} {RESET} Orden de bytes (predeterminado: little)

{YELLOW}{BOLD}ENSAMBLADOR / DESENSAMBLADOR (requiere pwntools):{RESET}
  {PINK}asm CÓDIGO    {RESET} Ensambla assembly → shellcode
  {PINK}disasm HEX    {RESET} Desensambla shellcode → assembly
  {CYAN}-c, --cpu ARCH   {RESET} Arquitectura: x86, amd64, arm, arm64 (predet.: amd64)
  {CYAN}-b, --badchars-opt{RESET} Resalta en rojo los bad chars del shellcode generado
  {DIM}Usa -c (nunca -a) para no chocar con -a/--address de la búsqueda ROP.{RESET}
  {DIM}pwntools solo se carga en este modo — los demás modos no dependen de él.{RESET}

{YELLOW}{BOLD}AYUDA Y MANUAL:{RESET}
  {CYAN}-h, --help       {RESET} Ayuda corta, lista para copiar y pegar (inglés)
  {CYAN}--help-br        {RESET} Ayuda corta en portugués
  {CYAN}--help-es        {RESET} Ayuda corta en español
  {CYAN}--man            {RESET} Manual completo en inglés (paginado)
  {CYAN}--man-br         {RESET} Manual completo en portugués
  {CYAN}--man-es         {RESET} Manual completo en español (este)

{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{YELLOW}{BOLD}EJEMPLOS DETALLADOS{RESET}

{CYAN}{BOLD}1. Búsqueda básica de ROP (buscar gadgets por instrucción){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "pop eax"{RESET}
   Busca gadgets que contengan 'pop eax', excluyendo null bytes y newlines

{CYAN}{BOLD}2. Usando Categorías Cookbook (patrones pre-construidos){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"{RESET}
   Usa patrones integrados para poner a cero registros (xor eax, eax | sub eax, eax)

{CYAN}{BOLD}3. Generar Hoja de Trucos ROP Completa{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" --milk{RESET}
   Exporta TODAS las categorías Cookbook a milk.txt (organizadas por categoría)

{CYAN}{BOLD}4. Incluir Gadgets Trampolín (JMP ESP, etc){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "jmp esp" --jmps{RESET}
   Predeterminado: oculta JMP/CALL | Con --jmps: incluye en resultados

{CYAN}{BOLD}5. Modo Búsqueda Sin Filtros (Trash Mode){RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "mov" --trash{RESET}
   Ignora límite MAX_GADGET_INSTRUCTIONS, muestra TODOS los resultados (bruto/sin filtrar)

{CYAN}{BOLD}6. Generar Payload de String{RESET}
   {GREEN}$ python roprop.py -b "\\x00\\x0a" --string "cmd.exe"{RESET}
   Genera instrucciones PUSH para "cmd.exe", evitando caracteres malos

{CYAN}{BOLD}7. Generar Dirección IP (con bypass NEG){RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77"{RESET}
   Genera forma normal y forma NEG-negada para direcciones IPv4

{CYAN}{BOLD}8. Combinar Múltiples Filtros{RESET}
   {GREEN}$ python roprop.py rop.txt "\\x00\\x0a" "xchg eax, esp" --address --seh --jmps{RESET}
   Búsqueda con: direcciones PERMITIDAS + segmento FS PERMITIDO + trampolines PERMITIDOS

{CYAN}{BOLD}9. Generar Payloads de 64-bit{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --string "test" --size 8{RESET}
   Cambia a instrucciones PUSH de 64-bit (qword)

{CYAN}{BOLD}10. Orden de Bytes Big-Endian{RESET}
   {GREEN}$ python roprop.py -b "\\x00" --ip-hex "192.168.1.77" --endian big{RESET}
   Útil para arquitecturas no-x86

{CYAN}{BOLD}11. Ensamblar Assembly (asm){RESET}
   {GREEN}$ python roprop.py asm "push rax; pop rbx" -c amd64{RESET}
   Convierte las instrucciones en shellcode (hex, escapado y listo para Python)

{CYAN}{BOLD}12. Desensamblar Shellcode (disasm){RESET}
   {GREEN}$ python roprop.py disasm "\\x31\\xc0\\x31\\xdb" -c x86{RESET}
   Acepta 31c0, "\\x31\\xc0", 0x31 0xc0 o "31 c0" — todos funcionan

{CYAN}{BOLD}13. Ensamblar Verificando Bad Chars{RESET}
   {GREEN}$ python roprop.py asm "xor eax, eax" -c x86 -b "\\x00\\x0a"{RESET}
   Ensambla y resalta en rojo cualquier bad char presente en el shellcode

{FOOTER}
"""
    show_help(help_text)
    sys.exit(0)

# ─────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Parser for the ROP search + generator modes.

    add_help=False on purpose: -h/--help is intercepted in main() and served
    by print_help_english(), so the user gets the short copy-paste help
    instead of argparse's auto-generated wall of text. The long-form
    reference lives in print_man_english() behind --man.
    """
    parser = argparse.ArgumentParser(
        prog="roprop",
        description=f"{CYAN}{BOLD}ROPROP v{VERSION}{RESET} — ROP Chain & Shellcode Filter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    # ──── POSITIONAL ARGUMENTS ─────────────────────────────────
    pos_grp = parser.add_argument_group(
        f"{CYAN}{BOLD}POSITIONAL ARGUMENTS{RESET}",
        f"{DIM}(Required for ROP mode; omit for generator mode){RESET}"
    )
    pos_grp.add_argument("file",     nargs="?",
                        help=f"Gadget file from rp++ or ROPgadget\n{DIM}Example: roprop.txt, gadgets.txt{RESET}")
    pos_grp.add_argument("badchars", nargs="?", default="",
                        help=f"Bad characters to exclude from results (format: \\\\x00\\\\x0a)\n{DIM}Example: '\\\\x00\\\\x0a', '\\\\x00\\\\x0d\\\\x20'{RESET}")
    pos_grp.add_argument("query",    nargs="?", default="",
                        help=f"Instruction pattern or Cookbook shortcut\n{DIM}Example: 'pop eax', 'Zero Out EAX', 'mov eax, esp'{RESET}")

    # ──── ROP SEARCH OPTIONS ───────────────────────────────────
    rop_grp = parser.add_argument_group(
        f"{CYAN}{BOLD}ROP SEARCH OPTIONS{RESET}",
        f"{DIM}(Filter & control gadget search behavior){RESET}"
    )
    rop_grp.add_argument("-m", "--milk", action="store_true",
                        help=f"Generate milk.txt with ALL Cookbook categories\n"
                             f"{DIM}Usage: python roprop.py rop.txt '\\\\x00\\\\x0a' --milk{RESET}\n"
                             f"{DIM}Output: Organized cheat sheet saved to milk.txt{RESET}")

    rop_grp.add_argument("-j", "--jmps", action="store_true",
                        help=f"Include gadgets ending with JMP/CALL (trampolines)\n"
                             f"{DIM}Default: Filtered out | With --jmps: Included in results{RESET}\n"
                             f"{DIM}Usage: python roprop.py rop.txt '\\\\x00\\\\x0a' 'xchg' --jmps{RESET}")

    rop_grp.add_argument("-a", "--address", action="store_true",
                        help=f"Include gadgets with hardcoded addresses (0x41414141, etc)\n"
                             f"{DIM}Default: Filtered out | With --address: Included in results{RESET}\n"
                             f"{DIM}Usage: python roprop.py rop.txt '\\\\x00\\\\x0a' 'mov' --address{RESET}")

    rop_grp.add_argument("-s", "--seh", action="store_true",
                        help=f"Include gadgets accessing FS segment (TEB/PEB/SEH)\n"
                             f"{DIM}Default: Blocked | With --seh: Allowed in results{RESET}\n"
                             f"{DIM}Usage: python roprop.py rop.txt '\\\\x00\\\\x0a' 'fs:' --seh{RESET}")

    rop_grp.add_argument("-t", "--trash", action="store_true",
                        help=f"Raw/unfiltered search mode — disables MAX_GADGET_INSTRUCTIONS limit\n"
                             f"{DIM}Use when you want ALL results, not just clean chains{RESET}\n"
                             f"{DIM}Usage: python roprop.py rop.txt '\\\\x00\\\\x0a' 'push' --trash{RESET}")

    # ──── GENERATOR OPTIONS ────────────────────────────────────
    gen_grp = parser.add_argument_group(
        f"{CYAN}{BOLD}GENERATOR OPTIONS (String / IP){RESET}",
        f"{DIM}(Generate PUSH assembly for payloads — omit ROP args){RESET}"
    )

    gen_grp.add_argument("-b", "--badchars-opt", dest="badchars_opt", default="",
                        help=f"Bad characters (use with --string/--ip-hex when no positional badchars)\n"
                             f"{DIM}Usage: python roprop.py -b '\\\\x00\\\\x0a' --string 'test'{RESET}\n"
                             f"{DIM}Avoids positional argument parsing{RESET}")

    gen_grp.add_argument("--string", metavar="STR",
                        help=f"Generate PUSH instructions for a string (bad-char aware)\n"
                             f"{DIM}Usage: python roprop.py -b '\\\\x00\\\\x0a' --string 'cmd.exe'{RESET}\n"
                             f"{DIM}Output: Assembly to push string on stack + alternatives (NEG/XOR){RESET}")

    gen_grp.add_argument("--ip-hex", dest="ip_hex", metavar="IP",
                        help=f"Generate PUSH instructions for IPv4 address (includes NEG bypass)\n"
                             f"{DIM}Usage: python roprop.py -b '\\\\x00' --ip-hex '192.168.1.77'{RESET}\n"
                             f"{DIM}Output: Normal hex + NEG-negated form (helps bypass bad chars){RESET}")

    gen_grp.add_argument("--size", type=int, choices=[4, 8], default=4,
                        help=f"Register size for generators: 4 = x86 (default), 8 = x64\n"
                             f"{DIM}Usage: python roprop.py -b '\\\\x00' --string 'test' --size 8{RESET}\n"
                             f"{DIM}Default: 4 (32-bit dword PUSH){RESET}")

    gen_grp.add_argument("--endian", choices=["little", "big"], default="little",
                        help=f"Byte order for generators: little (default) or big\n"
                             f"{DIM}Usage: python roprop.py -b '\\\\x00' --ip-hex '192.168.1.77' --endian big{RESET}\n"
                             f"{DIM}Default: little (x86/ARM standard){RESET}")

    return parser


def build_asm_parser() -> argparse.ArgumentParser:
    """
    Separate parser for the `asm` / `disasm` sub-commands.

    Kept apart from build_parser() on purpose: the ROP parser's positional
    layout (file / badchars / query) stays byte-for-byte what it always was,
    so no existing command line changes meaning. add_help=False for the same
    reason as build_parser() — see print_help_asm().
    """
    parser = argparse.ArgumentParser(
        prog="roprop",
        description=f"{CYAN}{BOLD}ROPROP v{VERSION}{RESET} — Assembler / Disassembler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument("command", choices=list(ASM_COMMANDS),
                        help="asm (assemble source) or disasm (disassemble shellcode)")
    parser.add_argument("code",
                        help="Assembly source for asm, or hex shellcode for disasm")
    parser.add_argument("-c", "--cpu", dest="arch", default="amd64",
                        choices=ARCH_CHOICES, metavar="ARCH",
                        help=f"Target architecture: {', '.join(ARCH_CHOICES)} (default: amd64)")
    parser.add_argument("-b", "--badchars-opt", dest="badchars_opt", default="",
                        metavar="BADCHARS",
                        help="Bad characters to flag in the shellcode (e.g. '\\x00\\x0a')")

    return parser


def run_asm_mode(argv: list[str]) -> None:
    """Handle `roprop.py asm ...` / `roprop.py disasm ...`."""
    # argparse's own -h is disabled here too, so serve the short asm help.
    if "-h" in argv or "--help" in argv:
        print_help_asm()

    args     = build_asm_parser().parse_args(argv)
    bc_bytes = parse_badchars(args.badchars_opt)

    print_banner_asm(args.command, args.arch, args.badchars_opt)
    _load_pwntools()          # fail fast, before the spinner burns two seconds

    try:
        if args.command == "asm":
            show_spinner("Assembling")
            shellcode = assemble(args.code, args.arch)
            format_asm_output(args.code, shellcode, args.arch, bc_bytes)
            done = f"{GREEN}{BOLD}✔  Assembly complete.{RESET}  " \
                   f"{CYAN}{BOLD}{len(shellcode)}{RESET}{WHITE} byte(s) produced.{RESET}"
        else:
            raw = parse_shellcode_hex(args.code)
            show_spinner("Disassembling")
            asm_text = disassemble(raw, args.arch)
            format_disasm_output(raw, asm_text, args.arch, bc_bytes)
            done = f"{GREEN}{BOLD}✔  Disassembly complete.{RESET}  " \
                   f"{CYAN}{BOLD}{len(raw)}{RESET}{WHITE} byte(s) decoded.{RESET}"
    except ValueError as exc:
        print(f"  {RED}{BOLD}✖  {exc}{RESET}\n")
        print_signature()
        sys.exit(1)

    print(SEP)
    print(f"  {done}")
    print(SEP + "\n")
    print_signature()

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main() -> None:
    # ── Manual (--man family) — long form, paged ──────────────
    # Checked before everything else so `roprop.py asm --man` works too.
    if "--man-br" in sys.argv:
        print_man_portuguese()
    if "--man-es" in sys.argv:
        print_man_spanish()
    if "--man" in sys.argv:
        print_man_english()

    # ── Short help (--help family) — terse, copy-paste ────────
    if "--help-br" in sys.argv or "-h-br" in sys.argv:
        print_help_portuguese()
    if "--help-es" in sys.argv or "-h-es" in sys.argv:
        print_help_spanish()

    # ── Assembler / Disassembler front door ───────────────────
    # Only a first positional of exactly "asm" or "disasm" is routed here.
    # Anything else falls straight through to the original ROP parser, so
    # every pre-existing command line keeps parsing exactly as before.
    if len(sys.argv) > 1 and sys.argv[1] in ASM_COMMANDS:
        run_asm_mode(sys.argv[1:])
        return

    # ── Short help in English (argparse's -h is disabled) ─────
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help_english()

    parser = build_parser()
    args   = parser.parse_args()

    # Resolve bad chars from either source
    bc_str  = args.badchars_opt if args.badchars_opt else args.badchars
    bc_bytes = parse_badchars(bc_str)

    # ── Generator mode ────────────────────────────────────────
    if args.string or args.ip_hex:
        target = args.string or args.ip_hex
        print_banner_generator(target, bc_str)
        show_spinner("Generating payload")

        if args.string:
            cmd_string(args.string, bc_bytes, args.size, args.endian)
        if args.ip_hex:
            cmd_ip(args.ip_hex, bc_bytes)

        print_signature()
        sys.exit(0)

    # ── ROP Finder mode ───────────────────────────────────────
    if not args.file:
        parser.error(
            "Provide a gadget file (e.g. rop.txt) or use --string / --ip-hex.\n"
            "Run  python roprop.py --help  for usage."
        )

    if not args.milk and not args.query:
        parser.error("Provide a search query or use --milk.")

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        print(f"\n  {RED}[!] File not found: '{args.file}'{RESET}\n")
        sys.exit(1)

    # ── Milk mode (full Cookbook export) ──────────────────────
    if args.milk:
        print_banner_rop(
            "ALL", bc_str, MAX_GADGET_INSTRUCTIONS,
            args.jmps, args.address, args.seh,
            is_milk=True, is_trash=args.trash,
        )
        show_spinner("Scanning all Cookbook categories")

        total = 0
        with open("milk.txt", "w", encoding="utf-8") as out:
            out.write("# ============================================================\n")
            out.write("# THE MILK — ROP Gadgets Cheat Sheet\n")
            out.write(f"# Bad characters excluded: {bc_str}\n")
            out.write("# ============================================================\n\n")

            for category, patterns in COOKBOOK.items():
                pattern = "(" + "|".join(patterns) + ")"
                results = search_gadgets(
                    lines, bc_bytes, pattern,
                    args.jmps, args.address, args.seh, args.trash,
                )
                if results:
                    total += len(results)
                    out.write(f"\n## ───── {category.upper()} ─────\n")
                    out.write("─" * 60 + "\n")
                    for r in results:
                        out.write(strip_ansi(format_gadget(r, no_color=True)) + "\n")

        print(f"  {GREEN}{BOLD}✔  milk.txt generated successfully!{RESET}")
        print(f"  {WHITE}Total gadgets found:{RESET}  {CYAN}{BOLD}{total}{RESET}\n")
        print_signature()
        return

    # ── Normal search mode ────────────────────────────────────
    query_low = args.query.lower()
    pattern   = query_low

    # Cookbook shortcut lookup
    cookbook_lower = {k.lower(): v for k, v in COOKBOOK.items()}
    if query_low in cookbook_lower:
        pattern = "(" + "|".join(cookbook_lower[query_low]) + ")"

    print_banner_rop(
        args.query, bc_str, MAX_GADGET_INSTRUCTIONS,
        args.jmps, args.address, args.seh, is_trash=args.trash,
    )
    show_spinner()

    results = search_gadgets(
        lines, bc_bytes, pattern,
        args.jmps, args.address, args.seh, args.trash,
    )

    for r in results:
        print(format_gadget(r))

    print(SEP)
    if results:
        print(f"  {GREEN}{BOLD}✔  Search complete.{RESET}  {CYAN}{BOLD}{len(results)}{RESET}{WHITE} gadget(s) found.{RESET}")
    else:
        print(f"  {RED}{BOLD}✖  No gadgets matched the criteria.{RESET}")
    print(SEP + "\n")
    print_signature()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {DIM}Interrupted by user.{RESET}\n")
        sys.exit(130)