[![Boosty](https://img.shields.io/badge/Boosty-Buy_me_a_coffee-FF7143?logo=boosty&logoColor=white&style=for-the-badge)](https://boosty.to/danusha/donate)

> 🇷🇺 На русском: [README.ru.md](README.ru.md)

# xgecu-t48-reverse

Reverse-engineered USB protocol notes and a Python prototype for talking
to the **XGecu T48 (TL866-3G)** universal programmer, with a focus on
**eMMC** read/write operations (including in-circuit / ISP).

The XGecu T48 is a popular universal chip programmer; its first-party
software (`Xgpro`) is Windows-only and the device's USB protocol is
undocumented. The open-source [`minipro`](https://gitlab.com/DavidGriffith/minipro)
project covers the classic-chip part of the protocol but explicitly does
**not** implement eMMC. This repository documents the eMMC extension of
the protocol — what the wire-format actually looks like — and ships a
small Python prototype that uses the same encoding.

> **Status: pre-hardware.** The protocol was extracted from static
> analysis of `Xgpro.exe` (PE32, WinUSB). All three command encodings
> that were directly decoded from the binary (CMD6 SWITCH→RPMB,
> SWITCH→USER, SWITCH→HS-200) reproduce byte-for-byte. Things that
> require a real device (init handshake details, response framing,
> response timing) are noted as TBD and will be validated against a USB
> capture once the programmer arrives.

## What's in here

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the full reverse-engineering
  write-up: USB identity (`a466:0a53`, WinUSB), endpoint roles
  (EP1 OUT/IN command + EP2 OUT bulk), the top-opcode / sub-opcode
  hierarchy, eMMC command table, init flow, RPMB frame layout, the
  `.alg` algorithm-file format, and the bulk transfer formats.
- [`docs/ISP_SETTINGS.md`](docs/ISP_SETTINGS.md) — a plain-language
  reference for the Xgpro **eMMC ISP settings** (bus width, VCCQ,
  `ICSP_VCC Enable`, CLK, `Vcc current Imax`, partitions, RST_n wiring):
  what each does and what to enable / disable, cross-checked against the
  wire captures. Russian: [`ISP_SETTINGS.ru.md`](docs/ISP_SETTINGS.ru.md).
- [`examples/t48_emmc.py`](examples/t48_emmc.py) — a small pyusb
  prototype: connect to the T48 by VID:PID, build the documented
  packets, and call them through high-level methods
  (`switch_partition`, `read_ecsd`, `bulk_read`, RPMB frame builder,
  etc.). Has an offline sanity test that verifies the three decoded
  CMD6 SWITCH arguments match the bytes seen in `Xgpro.exe`. Every USB
  transfer can be logged to a file (`T48Emmc(log_path=…)`) so a real
  session becomes ground truth for the protocol doc.
- [`examples/first_contact.py`](examples/first_contact.py) — a
  **zero-risk** first-session probe to run the moment a T48 is plugged
  in: `connect → identify → measure voltages → status → read pins`. It
  applies **no programming voltage**, needs **no chip** and **no
  eMMC-ISP adapter**, and logs every transfer. The safe way to validate
  the transport and the classic opcodes before touching a chip.
- [`tools/extract_alg.py`](tools/extract_alg.py) — standalone unpacker
  for the proprietary `.alg` files that ship with `Xgpro`. Each `.alg`
  contains a zero-RLE-compressed Xilinx Spartan-6 FPGA bitstream
  (340 604 bytes uncompressed) with a 32-bit CRC. No `.alg` files
  themselves are included — bring your own from a legitimate Xgpro
  install.

## Quick look at the protocol

A `Xgpro` USB command on EP1 OUT starts with a 1-byte top-opcode. The
ones in the classic range (`0x02..0x3F`) are already implemented by
`minipro`. The eMMC extension adds these top-opcodes:

| Top-opcode | Purpose                                              |
|------------|------------------------------------------------------|
| `0x08`     | Long-recv envelope (e.g. sub-op `0x48` → read 512 B) |
| `0x14`     | Bulk-write setup before N × 512 B on EP2 OUT         |
| `0x21`     | eMMC init / algorithm select                         |
| `0x27`     | eMMC sub-command dispatcher (sub-op in byte 1)       |

For `0x27`-class commands the layout is 8 bytes:
`[0x27][sub-op][u16 = 0][u32 arg LE]`. Among the sub-ops the **CMD6
SWITCH** encoding is the most informative: the 32-bit `arg` is exactly
the JEDEC eMMC CMD6 argument in big-endian, so e.g.

```
SWITCH PARTITION_CONFIG → RPMB     →  arg = 0x01B30300
SWITCH HS_TIMING        → HS-200   →  arg = 0x01AF0100
restore PARTITION_ACCESS → USER    →  arg = 0x02B30700  (CLEAR_BITS of 0x07)
```

See `docs/PROTOCOL.md` §9 for the full table.

## Try the prototype offline

```bash
pip install pyusb
python3 examples/t48_emmc.py
```

This runs the byte-level sanity test without touching any hardware:

```
== Проверка структур пакетов (offline) ==
  cmd_A(SWITCH→RPMB)        = 274600000003b301
  cmd_A(SWITCH→USER restore)= 274600000007b302
  cmd_A(SWITCH→HS200)       = 274600000001af01
  ...
[OK] Все три расшифрованные команды сходятся с реверсом Xgpro.exe.
```

With a T48 plugged in, `python3 examples/t48_emmc.py --connect` will
attempt to open the device via libusb. On Linux you may need a udev
rule to grant your user access to the device interface; on Windows the
official WinUSB driver from XGecu is fine.

For the **first** run on a fresh device, prefer the safe probe — it
applies no voltage, needs no chip, and saves a full transfer trace:

```bash
python3 examples/first_contact.py          # → t48_first_contact.log
```

## Unpacking a `.alg` (optional)

If you want to look at the FPGA bitstream that ships with `Xgpro` for a
given chip family, the unpacker writes the raw 340604-byte payload:

```bash
python3 tools/extract_alg.py path/to/Xgpro/algorithm/EMMC_41_18.alg
# → EMMC_41_18.bit  (340604 bytes, with 16-byte 0xFF preamble + FPGA sync)
```

## What's *not* here

Per the project's purpose this repository contains only original
material — the reverse-engineering write-up and our own code that
*talks the documented protocol*. It deliberately does **not** ship:

- any binary from XGecu (`Xgpro.exe`, drivers, firmware updates)
- any `.alg` algorithm files
- the chip database (`InfoIC2Plus.dll` dump)
- decompressed FPGA bitstreams

Those are XGecu's copyrighted material. The `Xgpro` software is
available for free from the manufacturer (https://www.xgecu.com/), and
the `dumpic` tool in `minipro` produces the chip-database dump locally
from a legitimate install.

## Why this exists

The intended consumer of this material is a separate eMMC-reader
application that already supports other USB-eMMC backends and wants to
add the T48 as one more backend on Windows and Linux. Documenting the
protocol publicly is also useful for anyone running the T48 from Linux
who wants something more programmable than running `Xgpro` under Wine.

This work piggybacks on the excellent [`minipro`](https://gitlab.com/DavidGriffith/minipro)
(GPL-3.0) — it already implements the shared T48 transport (opcodes
`0x02..0x3F`, USB handshake, voltage / clock control) — and on
[`radiomanV/TL866`](https://github.com/radiomanV/TL866) for the firmware
side of the device family.

## License

[MIT](LICENSE). Reverse engineering for the purpose of interoperability
between independently-developed software and the hardware its owner
purchased.

---

[![Boosty](https://img.shields.io/badge/Boosty-Buy_me_a_coffee-FF7143?logo=boosty&logoColor=white&style=for-the-badge)](https://boosty.to/danusha/donate)
