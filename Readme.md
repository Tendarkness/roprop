# roprop

```
  ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████╗
  ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔═══╝
  ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝
  v4.0 — ROP Chain, Shellcode Filter & Assembler  |  exploit dev & CTF
```

> **This README is available in two languages · Este README está disponível em dois idiomas**
> **[🇬🇧 English](#english)** · **[🇧🇷 Português](#português)**
>
> The tool runs in English by default. `--help` is short and copy-paste ready;
> `--man` opens the full manual in a pager. Both come in `-br` (Portuguese) and
> `-es` (Spanish) variants.
> A ferramenta roda em inglês por padrão. O `--help` é curto e feito para copiar
> e colar; o `--man` abre o manual completo paginado. Os dois têm versão `-br`
> (português) e `-es` (espanhol).

---
---

# English

ROP gadget filter, payload generator and assembler/disassembler in a single
Python script — built for exploit development and CTF.

## Install

```bash
# 1. clone the repository
git clone https://github.com/Tendarkness/roprop.git
cd roprop

# 2. run it (gadget searching needs no dependency at all)
python3 roprop.py --help
```

Optional — enables the `asm` / `disasm` modes:

```bash
pip install pwntools
```

If your distro complains about *externally-managed-environment* (recent
Kali/Debian):

```bash
pip install --break-system-packages pwntools
# or, if you prefer to isolate it:
python3 -m venv .venv && source .venv/bin/activate && pip install pwntools
```

To call it from anywhere:

```bash
chmod +x roprop.py
sudo ln -s "$(pwd)/roprop.py" /usr/local/bin/roprop
roprop --help
```

Update later:

```bash
git pull
```

## Requirements

| Item | Version | Required |
|---|---|---|
| Python | 3.9+ | yes |
| pwntools | any | **only** for `asm` / `disasm` |
| colorama | any | Windows only, without VT support (automatic fallback) |

`pwntools` is imported **on demand**: gadget searching and the generators run
fine on a machine without it, and you don't pay its import time on every search.

## The four modes

| Mode | Command | Purpose |
|---|---|---|
| ROP search | `roprop.py <file> <badchars> <query>` | find clean gadgets in an rp++/ROPgadget dump |
| Milk | `roprop.py <file> <badchars> --milk` | export a full cheat sheet to `milk.txt` |
| Generator | `roprop.py -b <badchars> --string/--ip-hex` | build PUSH chains for a string or IP, dodging badchars |
| Assembler | `roprop.py asm/disasm <code> -c <arch>` | assembly ⇄ shellcode with badchar verification |

## Producing the gadget file

roprop does **not** parse binaries — it filters the output of whoever already
extracted the gadgets:

```bash
# Windows / rp++
rp-win-x86.exe -f target.dll -r 5 --va 0 > rop.txt

# Linux / ROPgadget
ROPgadget --binary ./target --depth 5 > rop.txt
```

## Usage

### 1. Gadget search

```bash
python3 roprop.py rop.txt "\x00\x0a" "pop eax"
```

```
  ─────────────────────────────────────────────────────────────────
  Target Query   :  pop eax
  Bad Characters :  \x00\x0a
  Max Instrs     :  5  (ignored in trash mode)
  Trampolines    :  hidden
  Hard Addresses :  filtered
  FS / SEH       :  blocked
  Trash Mode     :  off
  ─────────────────────────────────────────────────────────────────

  ┌─ 0x10035512  │  push esp ; pop eax ; ret  ;
  │  ▲  Clobbered: EAX
  │
  │  rop += pack('<L', 0x10035512)  # push esp ; pop eax ; ret  ;
  └────────────────────────────────────────────────────────────

  ┌─ 0x10011a2b  │  pop eax ; ret  ;
  │  ▲  Clobbered: EAX
  │
  │  rop += pack('<L', 0x10011a2b)  # pop eax ; ret  ;
  │  rop += pack('<L', 0x50505050)       # padding
  └────────────────────────────────────────────────────────────

  ┌─ 0x100b5678  │  pop eax ; ret 0x0006  ;
  │  ▲  Clobbered: EAX
  │  ⚠  RETN detected — requires 1 extra DWORD(s) on stack
  │  ✖  Stack misalignment: 2 byte(s) remainder!
  └────────────────────────────────────────────────────────────
```

What roprop does for you on every gadget:

- drops addresses containing a badchar **before** showing them
- lists the registers destroyed (`Clobbered`)
- computes the padding from `pop` and from `retn 0xNNNN`, and writes the padding line for you
- **warns when `retn` misaligns the stack** (remainder not a multiple of 4)
- sorts from the cleanest gadget to the dirtiest
- hands you the `rop += pack('<L', ...)` line ready to paste into the exploit

### 2. Cookbook — search by intent

Instead of memorising the instruction, ask for the effect:

```bash
python3 roprop.py rop.txt "\x00\x0a" "Zero Out EAX"
python3 roprop.py rop.txt "\x00\x0a" "Stack Pivot"
python3 roprop.py rop.txt "\x00\x0a" "Write-What-Where (Any Register)"
```

<details>
<summary>The 18 available categories</summary>

| Category | Covers |
|---|---|
| `Get ESP (Stack Pointer)` | `push esp/pop r`, `mov r, esp` |
| `Zero Out EAX` … `EDI` | `xor r,r` / `sub r,r` / `and r,0` (6 categories) |
| `Increment Register` | `inc r`, `add r, 1` |
| `Decrement Register` | `dec r`, `sub r, 1` |
| `Negate Register` | `neg r` |
| `Add (Offset)` | `add eax, r` |
| `Subtract (Offset)` | `sub eax, r` |
| `Dereference EAX (Read Memory)` | `mov eax, [eax]` |
| `Dereference ESI (Read Memory)` | `mov esi, [esi]` |
| `Write-What-Where (Any Register)` | `mov [r1], r2` |
| `Stack Pivot` | `xchg eax, esp`, `mov esp, r` |
| `JMP ESP / Trampoline` | `jmp esp`, `call esp` |
| `TEB/PEB Read (FS Segment)` | any `fs:` |

</details>

### 3. Milk — the full cheat sheet

```bash
python3 roprop.py rop.txt "\x00\x0a" --milk
```

Sweeps **every** Cookbook category and writes `milk.txt` organised by category,
colourless, ready to consult while building the chain.

### 4. String and IP generator

```bash
python3 roprop.py -b "\x00\x0a" --string "cmd.exe"
python3 roprop.py -b "\x00"     --ip-hex "192.168.1.77"
```

Splits the target into DWORDs and emits the `push` sequence in reverse order.
When a block lands on a badchar it **proposes the alternative automatically** —
NEG in-place, or XOR in-place when NEG is dirty too, never clobbering a register:

```console
$ python3 roprop.py -b "\x00\x0a\x2e" --string "cmd.exe"

  Generated Assembly (push in reverse order):

  ; [!] Bad char in block 'exe\x00'  (0x00657865)
  ; Alternative — NEG in-place (no register clobbering)
  push 0xff9a879b
  neg  dword [esp]

  ; [!] Bad char in block 'cmd.'  (0x2e646d63)
  ; Alternative — NEG in-place (no register clobbering)
  push 0xd19b929d
  neg  dword [esp]
```

For x64: `--size 8`. For big-endian architectures: `--endian big`.

### 5. Assembler / Disassembler

```bash
python3 roprop.py asm "push rax; pop rbx" -c amd64
python3 roprop.py disasm "\x31\xc0\x31\xdb" -c x86
```

`disasm` accepts the shellcode in whatever shape you happen to have it:

```
5058      50 58      50,58      \x50\x58      0x50 0x58
```

And `-b` turns on badchar verification over the produced shellcode — which is
the reason both tools live in the same script:

```bash
python3 roprop.py asm "xor eax, eax; mov ebx, 1" -c x86 -b "\x00\x0a"
```

```
  Source:
    xor eax, eax
    mov ebx, 1

  Architecture   :  x86
  Length         :  7 byte(s)

  Hex:
    31c0bb01000000

  Escaped:
    \x31\xc0\xbb\x01\x00\x00\x00

  Python:
    shellcode = b"\x31\xc0\xbb\x01\x00\x00\x00"

  ✖  Bad char(s) present in shellcode: \x00
     Rewrite the instruction(s) or encode the payload.
```

Architectures: `x86`, `amd64`, `arm`, `arm64`.

> To assemble ARM/ARM64 on an x86 machine, pwntools needs the cross binutils:
> `sudo apt install binutils-arm-linux-gnueabi binutils-aarch64-linux-gnu`

## Flag reference

**Positional (ROP search)**

| Argument | Description |
|---|---|
| `file` | gadget dump from rp++ or ROPgadget |
| `badchars` | characters to exclude, format `\x00\x0a` |
| `query` | instruction or Cookbook category name |

**ROP search**

| Flag | Effect |
|---|---|
| `-m`, `--milk` | export every category to `milk.txt` |
| `-j`, `--jmps` | include gadgets ending in `jmp`/`call` |
| `-a`, `--address` | include gadgets with hardcoded addresses (`0x41414141`) |
| `-s`, `--seh` | allow gadgets touching `fs:` (TEB/PEB/SEH) |
| `-t`, `--trash` | raw mode — drops the 5-instruction limit |

**Generator**

| Flag | Effect |
|---|---|
| `-b`, `--badchars-opt` | badchars (replaces the positional one) |
| `--string STR` | generate PUSH for the string |
| `--ip-hex IP` | generate PUSH for the IPv4, with NEG form |
| `--size {4,8}` | 4 = x86 (default), 8 = x64 |
| `--endian {little,big}` | byte order |

**Assembler**

| Flag | Effect |
|---|---|
| `asm CODE` | assembly → shellcode |
| `disasm HEX` | shellcode → assembly |
| `-c`, `--cpu` | `x86`, `amd64`, `arm`, `arm64` (default `amd64`) |
| `-b`, `--badchars-opt` | highlight badchars in the produced shellcode |

**Help**

| Flag | Effect |
|---|---|
| `-h`, `--help` | short help, copy-paste ready (also `--help-br`, `--help-es`) |
| `--man` | full manual in a pager (also `--man-br`, `--man-es`) |

> Architecture is `-c/--cpu` and never `-a`, because `-a` already belongs to
> `--address` in the ROP search. No flag collides between modes.

## Two levels of help, in three languages

`--help` is the quick reference: one screen, no pager, every example on its own
line so you can select and paste it straight into the shell.

```bash
python3 roprop.py --help        # English (default)
python3 roprop.py --help-br     # Portuguese
python3 roprop.py --help-es     # Spanish
python3 roprop.py asm --help    # assembler/disassembler only
```

`--man` is the full manual: every flag explained, 13 worked examples, opened in
a pager that starts at the top. Scroll with the mouse wheel, arrows, PgUp/PgDn;
`q` quits.

```bash
python3 roprop.py --man         # English
python3 roprop.py --man-br      # Portuguese
python3 roprop.py --man-es      # Spanish
```

Redirecting either one to a file gives clean plain text, without the pager
decoration: `python3 roprop.py --man > manual.txt`.

## What's new

**v4.0**

- `--help` split from `--man`: short copy-paste reference vs. full manual
- `--man`, `--man-br`, `--man-es` open in a pager, starting at the top
- mouse-wheel scrolling in the pager (`less --mouse`, auto-detected)
- centered scroll hint so it's obvious there's more below
- dropped the dead argparse formatter classes

**v3.1**

- `asm` and `disasm` modes integrated, powered by pwntools
- badchar verification over the assembled shellcode (`-b` in assembler mode)
- tolerant hex parser in `disasm` (`\x`, `0x`, space, comma)
- help footers unified into a single constant
- pwntools import deferred: gadget searching stays dependency-free

Every v3.0 feature is untouched — old command lines still parse exactly as
before.

## Legal notice

Research and exploit development tool, for use in labs, CTFs, certifications
and tests **authorised in writing**. Using it against systems without
authorisation is a crime. Responsibility for use lies with whoever runs it.

## Author

Built by **peanut**.

If roprop saved you time on a chain, leave a ⭐ on the repository.

---
---

# Português

Filtro de ROP gadgets, gerador de payload e assembler/disassembler em um único
script Python — feito para desenvolvimento de exploit e CTF.

## Instalação

```bash
# 1. clonar o repositório
git clone https://github.com/Tendarkness/roprop.git
cd roprop

# 2. testar (não precisa instalar nada para a busca de gadgets)
python3 roprop.py --help
```

Opcional — habilita os modos `asm` / `disasm`:

```bash
pip install pwntools
```

Se o seu Linux reclamar de *externally-managed-environment* (Kali/Debian
recentes):

```bash
pip install --break-system-packages pwntools
# ou, preferindo isolar:
python3 -m venv .venv && source .venv/bin/activate && pip install pwntools
```

Para chamar de qualquer diretório:

```bash
chmod +x roprop.py
sudo ln -s "$(pwd)/roprop.py" /usr/local/bin/roprop
roprop --help
```

Atualizar depois:

```bash
git pull
```

## Requisitos

| Item | Versão | Obrigatório |
|---|---|---|
| Python | 3.9+ | sim |
| pwntools | qualquer | **só** para `asm` / `disasm` |
| colorama | qualquer | só no Windows sem suporte a VT (fallback automático) |

O `pwntools` é importado **sob demanda**: a busca de gadgets e os geradores
rodam normalmente numa máquina sem ele instalado, e você não paga o tempo de
import dele em cada busca.

## Os quatro modos

| Modo | Comando | Para quê |
|---|---|---|
| Busca ROP | `roprop.py <arquivo> <badchars> <query>` | achar gadgets limpos num dump do rp++/ROPgadget |
| Milk | `roprop.py <arquivo> <badchars> --milk` | exportar um cheat sheet completo para `milk.txt` |
| Gerador | `roprop.py -b <badchars> --string/--ip-hex` | montar PUSH de string ou IP driblando badchars |
| Assembler | `roprop.py asm/disasm <código> -c <arch>` | assembly ⇄ shellcode com verificação de badchar |

## Gerando o arquivo de gadgets

O roprop **não** lê binários — ele filtra a saída de quem já extraiu os gadgets:

```bash
# Windows / rp++
rp-win-x86.exe -f target.dll -r 5 --va 0 > rop.txt

# Linux / ROPgadget
ROPgadget --binary ./target --depth 5 > rop.txt
```

## Uso

### 1. Busca de gadgets

```bash
python3 roprop.py rop.txt "\x00\x0a" "pop eax"
```

```
  ─────────────────────────────────────────────────────────────────
  Target Query   :  pop eax
  Bad Characters :  \x00\x0a
  Max Instrs     :  5  (ignored in trash mode)
  Trampolines    :  hidden
  Hard Addresses :  filtered
  FS / SEH       :  blocked
  Trash Mode     :  off
  ─────────────────────────────────────────────────────────────────

  ┌─ 0x10035512  │  push esp ; pop eax ; ret  ;
  │  ▲  Clobbered: EAX
  │
  │  rop += pack('<L', 0x10035512)  # push esp ; pop eax ; ret  ;
  └────────────────────────────────────────────────────────────

  ┌─ 0x10011a2b  │  pop eax ; ret  ;
  │  ▲  Clobbered: EAX
  │
  │  rop += pack('<L', 0x10011a2b)  # pop eax ; ret  ;
  │  rop += pack('<L', 0x50505050)       # padding
  └────────────────────────────────────────────────────────────

  ┌─ 0x100b5678  │  pop eax ; ret 0x0006  ;
  │  ▲  Clobbered: EAX
  │  ⚠  RETN detected — requires 1 extra DWORD(s) on stack
  │  ✖  Stack misalignment: 2 byte(s) remainder!
  └────────────────────────────────────────────────────────────
```

O que o roprop faz por você em cada gadget:

- descarta endereços que contenham badchar **antes** de mostrar
- lista os registradores destruídos (`Clobbered`)
- calcula o padding de `pop` e de `retn 0xNNNN` e já escreve a linha de padding
- **avisa quando o `retn` desalinha a stack** (resto não múltiplo de 4)
- ordena do gadget mais limpo para o mais sujo
- entrega a linha `rop += pack('<L', ...)` pronta para colar no exploit

### 2. Cookbook — busca por intenção

Em vez de decorar a instrução, peça o efeito:

```bash
python3 roprop.py rop.txt "\x00\x0a" "Zero Out EAX"
python3 roprop.py rop.txt "\x00\x0a" "Stack Pivot"
python3 roprop.py rop.txt "\x00\x0a" "Write-What-Where (Any Register)"
```

<details>
<summary>As 18 categorias disponíveis</summary>

| Categoria | Cobre |
|---|---|
| `Get ESP (Stack Pointer)` | `push esp/pop r`, `mov r, esp` |
| `Zero Out EAX` … `EDI` | `xor r,r` / `sub r,r` / `and r,0` (6 categorias) |
| `Increment Register` | `inc r`, `add r, 1` |
| `Decrement Register` | `dec r`, `sub r, 1` |
| `Negate Register` | `neg r` |
| `Add (Offset)` | `add eax, r` |
| `Subtract (Offset)` | `sub eax, r` |
| `Dereference EAX (Read Memory)` | `mov eax, [eax]` |
| `Dereference ESI (Read Memory)` | `mov esi, [esi]` |
| `Write-What-Where (Any Register)` | `mov [r1], r2` |
| `Stack Pivot` | `xchg eax, esp`, `mov esp, r` |
| `JMP ESP / Trampoline` | `jmp esp`, `call esp` |
| `TEB/PEB Read (FS Segment)` | qualquer `fs:` |

</details>

### 3. Milk — cheat sheet completo

```bash
python3 roprop.py rop.txt "\x00\x0a" --milk
```

Varre **todas** as categorias do Cookbook e grava `milk.txt` organizado por
categoria, sem cor, pronto para consultar durante a montagem da chain.

### 4. Gerador de string e de IP

```bash
python3 roprop.py -b "\x00\x0a" --string "cmd.exe"
python3 roprop.py -b "\x00"     --ip-hex "192.168.1.77"
```

Quebra o alvo em DWORDs e emite os `push` na ordem reversa. Quando um bloco cai
num badchar, ele **propõe a alternativa automaticamente** — NEG in-place, ou XOR
in-place quando o NEG também estiver sujo, sempre sem sujar registrador:

```console
$ python3 roprop.py -b "\x00\x0a\x2e" --string "cmd.exe"

  Generated Assembly (push in reverse order):

  ; [!] Bad char in block 'exe\x00'  (0x00657865)
  ; Alternative — NEG in-place (no register clobbering)
  push 0xff9a879b
  neg  dword [esp]

  ; [!] Bad char in block 'cmd.'  (0x2e646d63)
  ; Alternative — NEG in-place (no register clobbering)
  push 0xd19b929d
  neg  dword [esp]
```

Para x64: `--size 8`. Para arquitetura big-endian: `--endian big`.

### 5. Assembler / Disassembler

```bash
python3 roprop.py asm "push rax; pop rbx" -c amd64
python3 roprop.py disasm "\x31\xc0\x31\xdb" -c x86
```

O `disasm` aceita o shellcode em qualquer formato que você tenha em mãos:

```
5058      50 58      50,58      \x50\x58      0x50 0x58
```

E o `-b` liga a verificação de badchar sobre o shellcode gerado — que é o motivo
de as duas ferramentas viverem no mesmo script:

```bash
python3 roprop.py asm "xor eax, eax; mov ebx, 1" -c x86 -b "\x00\x0a"
```

```
  Source:
    xor eax, eax
    mov ebx, 1

  Architecture   :  x86
  Length         :  7 byte(s)

  Hex:
    31c0bb01000000

  Escaped:
    \x31\xc0\xbb\x01\x00\x00\x00

  Python:
    shellcode = b"\x31\xc0\xbb\x01\x00\x00\x00"

  ✖  Bad char(s) present in shellcode: \x00
     Rewrite the instruction(s) or encode the payload.
```

Arquiteturas: `x86`, `amd64`, `arm`, `arm64`.

> Para montar ARM/ARM64 numa máquina x86 o pwntools precisa do binutils cruzado:
> `sudo apt install binutils-arm-linux-gnueabi binutils-aarch64-linux-gnu`

## Referência de flags

**Posicionais (busca ROP)**

| Argumento | Descrição |
|---|---|
| `arquivo` | dump de gadgets do rp++ ou ROPgadget |
| `badchars` | caracteres a excluir, formato `\x00\x0a` |
| `query` | instrução ou nome de categoria do Cookbook |

**Busca ROP**

| Flag | Efeito |
|---|---|
| `-m`, `--milk` | exporta todas as categorias para `milk.txt` |
| `-j`, `--jmps` | inclui gadgets terminados em `jmp`/`call` |
| `-a`, `--address` | inclui gadgets com endereço hardcoded (`0x41414141`) |
| `-s`, `--seh` | libera gadgets que tocam `fs:` (TEB/PEB/SEH) |
| `-t`, `--trash` | modo bruto — remove o limite de 5 instruções |

**Gerador**

| Flag | Efeito |
|---|---|
| `-b`, `--badchars-opt` | badchars (substitui o posicional) |
| `--string STR` | gera PUSH para a string |
| `--ip-hex IP` | gera PUSH para o IPv4, com forma NEG |
| `--size {4,8}` | 4 = x86 (padrão), 8 = x64 |
| `--endian {little,big}` | ordem de bytes |

**Assembler**

| Flag | Efeito |
|---|---|
| `asm CÓDIGO` | assembly → shellcode |
| `disasm HEX` | shellcode → assembly |
| `-c`, `--cpu` | `x86`, `amd64`, `arm`, `arm64` (padrão `amd64`) |
| `-b`, `--badchars-opt` | destaca badchars no shellcode gerado |

**Ajuda**

| Flag | Efeito |
|---|---|
| `-h`, `--help` | ajuda curta, pronta para colar (também `--help-br`, `--help-es`) |
| `--man` | manual completo paginado (também `--man-br`, `--man-es`) |

> A arquitetura é `-c/--cpu` e nunca `-a`, porque `-a` já pertence a
> `--address` da busca ROP. Nenhuma flag colide entre os modos.

## Dois níveis de ajuda, em três idiomas

O `--help` é a referência rápida: cabe numa tela, não abre pager, e cada exemplo
fica numa linha só para você selecionar e colar direto no shell.

```bash
python3 roprop.py --help        # inglês (padrão)
python3 roprop.py --help-br     # português
python3 roprop.py --help-es     # espanhol
python3 roprop.py asm --help    # só o assembler/disassembler
```

O `--man` é o manual completo: cada flag explicada, 13 exemplos resolvidos,
aberto num pager que começa no topo. Role com o scroll do mouse, setas ou
PgUp/PgDn; `q` sai.

```bash
python3 roprop.py --man         # inglês
python3 roprop.py --man-br      # português
python3 roprop.py --man-es      # espanhol
```

Redirecionando qualquer um dos dois para arquivo sai texto limpo, sem a
decoração do pager: `python3 roprop.py --man > manual.txt`.

## Novidades

**v4.0**

- `--help` separado do `--man`: referência curta para colar vs. manual completo
- `--man`, `--man-br`, `--man-es` abrem paginados, começando no topo
- rolagem pelo scroll do mouse no pager (`less --mouse`, detectado automaticamente)
- aviso de scroll centralizado, deixando claro que tem mais conteúdo abaixo
- removidas as classes de formatter do argparse que ficaram sem uso

**v3.1**

- modos `asm` e `disasm` integrados, movidos a pwntools
- verificação de badchar sobre o shellcode montado (`-b` no modo assembler)
- parser de hex tolerante no `disasm` (`\x`, `0x`, espaço, vírgula)
- rodapés de ajuda unificados numa constante única
- import do pwntools adiado: a busca de gadgets continua sem dependência externa

Toda a funcionalidade da v3.0 permanece inalterada — a linha de comando antiga
continua sendo lida exatamente como antes.

## Aviso legal

Ferramenta de pesquisa e desenvolvimento de exploit, para uso em laboratório,
CTF, certificações e testes **autorizados por escrito**. Usar contra sistemas
sem autorização é crime. A responsabilidade pelo uso é de quem executa.

## Autor

Desenvolvido por **peanut**.

Se o roprop te economizou tempo numa chain, deixa uma ⭐ no repositório.