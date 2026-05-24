#!/usr/bin/env python3
"""
  ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████ 
  ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔═══╝
  ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝
  v3.0 — ROP Chain & Shellcode Filter  |  OSED/OSCE3
  A tool for exploit development and research (OSED/OSCE3).

Usage:
  python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  python roprop.py rop.txt "\\x00\\x0a" --milk
  python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.1.77"
"""

import sys
import re
import argparse
import time
import struct
import platform

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

VERSION       = "3.0"
MAX_GADGET_INSTRUCTIONS = 5

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
  {DIM}v{VERSION} — ROP Chain & Shellcode Filter  |  OSED/OSCE3{RESET}
"""

SEP = f"  {DIM}{'─' * 65}{RESET}"


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
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roprop",
        description=f"{CYAN}{BOLD}ROPROP v{VERSION}{RESET} — ROP Chain & Shellcode Filter",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""\
{YELLOW}Examples — String & IP generators:{RESET}
  python roprop.py -b "\\x00\\x0a" --string "cmd.exe"
  python roprop.py -b "\\x00\\x0a" --ip-hex "192.168.0.77"

{YELLOW}Examples — ROP gadget search:{RESET}
  python roprop.py rop.txt "\\x00\\x0a" "pop eax"
  python roprop.py rop.txt "\\x00\\x0a" "Zero Out EAX"
  python roprop.py rop.txt "\\x00\\x0a" --milk
  python roprop.py rop.txt "\\x00\\x0a" "jmp esp" --jmps --trash
""",
    )

    # Positional (ROP mode)
    parser.add_argument("file",     nargs="?", help="Gadget file from rp++ or ROPgadget.")
    parser.add_argument("badchars", nargs="?", default="", help=r"Bad characters  e.g. '\x00\x0a'")
    parser.add_argument("query",    nargs="?", default="", help="Assembly instruction or Cookbook shortcut.")

    # ROP search options
    rop_grp = parser.add_argument_group("ROP Search Options")
    rop_grp.add_argument("-m", "--milk",     action="store_true", help="Generate 'milk.txt' with all Cookbook categories.")
    rop_grp.add_argument("-j", "--jmps",     action="store_true", help="Include gadgets ending with JMP/CALL.")
    rop_grp.add_argument("-a", "--address",  action="store_true", help="Include gadgets with hardcoded addresses.")
    rop_grp.add_argument("-s", "--seh",      action="store_true", help="Include gadgets accessing FS segment (TEB/PEB/SEH).")
    rop_grp.add_argument("-t", "--trash",    action="store_true", help="Raw/unfiltered search — disables instruction count limit.")

    # Generator options
    gen_grp = parser.add_argument_group("Generator Options (String / IP)")
    gen_grp.add_argument("-b", "--badchars-opt", dest="badchars_opt", default="",
                         help="Bad chars without positional argument (use with --string/--ip-hex).")
    gen_grp.add_argument("--string",  help="Generate PUSH instructions for a string (bad-char aware).")
    gen_grp.add_argument("--ip-hex",  dest="ip_hex", help="Generate PUSH instructions for an IPv4 address (NEG evasion).")
    gen_grp.add_argument("--size",    type=int, choices=[4, 8], default=4,
                         help="Register size: 4 = x86 (default), 8 = x64.")
    gen_grp.add_argument("--endian",  choices=["little", "big"], default="little",
                         help="Byte order (default: little).")

    return parser

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main() -> None:
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
