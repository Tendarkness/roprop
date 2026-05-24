# ROPROP

```
  ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ 
  ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔═══╝
  ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝
  v3.0 — ROP Chain & Shellcode Filter  |  OSED/OSCE3
  A tool for exploit development and research (OSED/OSCE3).

```

> **The definitive ROP gadget filter and shellcode helper for exploit development.**  
> Designed for OSED/OSCE3 preparation and real-world Windows exploit research.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Gadget Search** | Filter rp++/ROPgadget output by instruction, quality, and constraints |
| 📖 **Cookbook Mode** | 16+ pre-built ROP categories with human-readable shortcuts |
| 🥛 **Milk Export** | Dump all Cookbook categories at once to `milk.txt` |
| 💀 **Bad Char Aware** | Automatically exclude gadgets with bad bytes in their address |
| 📦 **String Push Gen** | Generate `PUSH` sequences for any string, with NEG/XOR evasion |
| 🌐 **IP Push Gen** | Generate `PUSH` for IPv4 addresses with bad char alternatives |
| ⚙️ **Stack Analysis** | Detects clobbered registers, required padding, and RETN offsets |
| 🖥️ **Cross-Platform** | Works on Linux, macOS, and Windows (ANSI colors supported) |

---

## Requirements

- Python 3.10+
- **Linux / macOS:** No extra dependencies — ANSI colors work natively.
- **Windows:** Install [`colorama`](https://pypi.org/project/colorama/) for best color support:

```
pip install colorama
```

> Without `colorama`, ROPROP will try to enable Windows VT processing automatically (works on Windows 10 1511+).

---

## Usage

### ROP Gadget Search

```
python roprop.py <gadget_file> [badchars] [query] [options]
```

```
python roprop.py rop.txt "\x00\x0a" "pop eax"
python roprop.py rop.txt "\x00\x0a" "Zero Out EAX"
python roprop.py rop.txt "\x00\x0a" --milk
python roprop.py rop.txt "\x00\x0a" "jmp esp" --jmps --trash
```

### String / IP Generators

```
python roprop.py -b "\x00\x0a" --string "cmd.exe"
python roprop.py -b "\x00\x0a" --ip-hex "192.168.0.77"
python roprop.py -b "\x00\x0a" --string "/bin/sh" --size 4 --endian little
```

---

## Options

### ROP Search Options

| Flag | Description |
|---|---|
| `-m`, `--milk` | Generate `milk.txt` with all Cookbook categories |
| `-j`, `--jmps` | Include gadgets ending with JMP or CALL |
| `-a`, `--address` | Include gadgets containing hardcoded addresses |
| `-s`, `--seh` | Include gadgets accessing FS segment (TEB/PEB/SEH) |
| `-t`, `--trash` | Raw mode — disable instruction count limit |

### Generator Options

| Flag | Description |
|---|---|
| `-b`, `--badchars-opt` | Bad chars (use without positional args) |
| `--string` | Generate PUSH sequence for a string |
| `--ip-hex` | Generate PUSH for an IPv4 address |
| `--size` | Register size: `4` = x86 (default), `8` = x64 |
| `--endian` | Byte order: `little` (default) or `big` |

---

## Cookbook Categories

Use the category name as a query shortcut:

```
python roprop.py rop.txt "\x00\x0a" "Zero Out EAX"
python roprop.py rop.txt "\x00\x0a" "Stack Pivot"
python roprop.py rop.txt "\x00\x0a" "Write-What-Where (Any Register)"
```

| Category | Description |
|---|---|
| Get ESP (Stack Pointer) | Move ESP into a general-purpose register |
| Zero Out EAX/EBX/ECX/EDX/ESI/EDI | Clear a register without bad chars |
| Increment / Decrement Register | Adjust register values by 1 |
| Negate Register | `neg rX` for building values via inversion |
| Add / Subtract (Offset) | Arithmetic between registers |
| Dereference EAX / ESI | Read memory through a register |
| Write-What-Where (Any Register) | Write register value to a memory address |
| Stack Pivot | Redirect ESP to a controlled address |
| JMP ESP / Trampoline | Classic trampoline gadgets |
| TEB/PEB Read (FS Segment) | Access Thread/Process Environment Block |

---

## Gadget Output Format

For every matching gadget, ROPROP shows:

```
  ┌─ 0x10018a8e  │  xor eax, eax ; ret
  │  ▲  Clobbered: EAX
  │
  │  rop += pack('<L', 0x10018a8e)  # xor eax, eax ; ret
  └────────────────────────────────────────────────────────────
```

With any required padding:
```
  │  rop += pack('<L', 0x50505050)  * 2  # padding
```

---

## Generating a Gadget File

Use **rp++** to extract gadgets from a target binary:

```bash
# Linux / Windows
rp++ -f target.dll -r 5 > rop.txt

# Or with ROPgadget
ROPgadget --binary target.exe --rop > rop.txt
```

Then pass the output file to ROPROP.

---

## Example Workflow (OSED-style)

```python
# 1. Find a gadget to zero EAX
python roprop.py rop.txt "\x00\x0a" "Zero Out EAX"

# 2. Find a write-what-where primitive
python roprop.py rop.txt "\x00\x0a" "Write-What-Where (Any Register)"

# 3. Build the full cheat sheet
python roprop.py rop.txt "\x00\x0a" --milk

# 4. Encode a shell command string avoiding bad chars
python roprop.py -b "\x00\x0a\x20" --string "cmd.exe"

# 5. Encode a listener IP
python roprop.py -b "\x00\x0a" --ip-hex "192.168.1.100"
```

---

## Disclaimer

ROPROP is intended **for educational and authorized security research purposes only**.  
Use it solely on systems you own or have explicit written permission to test.  
The author assumes no responsibility for misuse.

---

## License

MIT License — see [`LICENSE`](LICENSE) for details.