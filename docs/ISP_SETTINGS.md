> 🇷🇺 На русском: [ISP_SETTINGS.ru.md](ISP_SETTINGS.ru.md)

# XGecu T48 — eMMC ISP settings reference

What each Xgpro setting does for **in-circuit (ISP) eMMC** work, and what
to enable / disable. Compiled from three sources: the UI strings and
logic of the installed `Xgpro.exe`, the official Xgpro user guide, and our
own wire-level captures (`docs/PROTOCOL.md` §33–§34, which show what each
choice actually does on the USB protocol).

Short quoted strings below (`"..."`) are verbatim from `Xgpro.exe`, kept
for interoperability.

---

## 1. IC selection — `AUTO_EMMC(ISP)_<width>bit_<VCCQ>` (the big one)

The chosen IC encodes **two** things at once, which we confirmed in the
captures:

- **Bus width** (1 / 4 / 8-bit). This is a host-side choice: it picks the
  FPGA bitstream and shows up as one byte in `BEGIN_TRANSACTION`
  (`0x51` = 1-bit, `0x54` = 4-bit; §33.6). There is **no** CMD6
  `BUS_WIDTH` switch sent to the eMMC — the programmer/adapter drives the
  bus in the selected mode.
  - **1-bit** — fewest wires, most tolerant of messy ISP wiring. *Start
    here.*
  - **4 / 8-bit** — faster, but needs more clean data lines and good
    signal integrity.
- **VCCQ (I/O voltage)** — `1.8V` or `3.3V` (see §4).

## 2. Interface: `ICSP port` vs `ZIF/SIP ADP`

- **ICSP port** — in-circuit, through the ISP connector. **Always use this
  for ISP eMMC.** Xgpro prompts: *"Connect <ICSP> to target board"*,
  *"Guaranteed: the ICSP connection is correct!"*.
- **ZIF/SIP ADP** — the on-board socket, for desoldered chips on a BGA
  adapter. Not for in-circuit.

## 3. `ICSP_VCC Enable` — who powers the target (the confusing one)

- **Enabled** → the T48 supplies VCC to the target over the ISP cable,
  **max 120 mA** (*"Option VCC power (MAX120ma) to the target board"*).
  Use when the board is unpowered and you want to power just the chip from
  the programmer.
- **Disabled** → the target is powered externally. In that case
  `Xgpro.exe` is explicit: **"If use external power don't connect VCC"** —
  physically leave the VCC line unconnected so two supplies don't fight.

Rule of thumb: power the chip from the T48 → *enable*; board already
powered → *disable* and don't wire VCC.

## 4. VCCQ — `1.8V` vs `3.3V`

- Most eMMC run `VCC = 3.3V / VCCQ = 1.8V` (the guide notes this is very
  stable).
- Many parts also read at 3.3V. `Xgpro.exe` warns for some:
  *"EMMC not Support 1.8V Low Voltage Supply"*, and on read failure:
  **"Reduce the CLK or switch VCCQ 1.8V<->3.3V for testing"**.
- Pick the level the chip is specified for; if reads fail, flip VCCQ.

## 5. `CLK` — bus clock

- Options: **`AUTO (MAX = 50 MHZ)`** plus manual 8…50 MHz, and HS modes
  (60/80 = HS200, 100/120/160 = HS400). Over ISP the practical ceiling is
  ~40–50 MHz.
- **Leave on AUTO.** If reads are unstable, **lower the CLK** — this is
  Xgpro's first troubleshooting step. Long or untidy ISP leads ⇒ lower
  clock.

## 6. `Vcc current Imax`

- Over-current limit (short protection). **`Default`** for normal use;
  lower it for extra protection when probing an unknown board (it trips
  sooner).

## 7. Partitions

Partition switching is CMD6 `SWITCH` to `PARTITION_CONFIG[179]`, confirmed
on the wire (§33.3):

| Partition | PARTITION_CONFIG value |
|-----------|------------------------|
| USER (main) | clear (`07 b3 02`) |
| BOOT1 | `01 b3 01` |
| BOOT2 | `02 b3 01` |
| RPMB  | `03 b3 01` |
| GPP1–4 | general-purpose partitions |

- Select which partitions to read / write / erase
  (*"Erase / Blank Check / Partition Selected"*). A full clone reads all
  system partitions + USER.
- **RPMB** needs an authentication key (HMAC). Without one:
  *"Authentication Key not yet programmed, RPMB not used"*.

## 8. Hardware (not software, but required for ISP to work)

- **RST_n**: after power-up, the eMMC `RST_n` must be high. If it reads 0,
  pull it to VCCQ with **~1 kΩ** — otherwise the chip stays in reset and
  never answers.
- **Grounds**: ISP has two GND lines; connect **both**, with the ground
  return **close to the CLK** line. Don't let CLK cross other signals.
- If unstable, a **2.2 µF** cap between VCC and GND helps
  (*"Connect a 2.2uf Capacitor between Pin VCC and Gnd"*).

## 9. TL;DR — a stable ISP-read starting point

1. IC: **`AUTO_EMMC(ISP)_1bit`** (move to 4-bit once wiring is proven);
   VCCQ per the chip.
2. Interface: **ICSP port**.
3. **ICSP_VCC Enable**: on if powering the chip from the T48 (≤120 mA);
   off + leave VCC unwired if the board is externally powered.
4. CLK: **AUTO**; lower it if reads error out.
5. Imax: **Default**.
6. Hardware: RST_n pulled to VCCQ (~1 kΩ), both GND near CLK.

Note: the ISP adapter authenticates itself to the T48 firmware (it reports
as `XGecu Directly` over USB opcode `0x24`, §33.1); none of the above is a
crypto setting — they are signal/electrical and partition choices.

---

## Sources

- Official Xgpro user guide:
  [Jameco PDF](https://www.jameco.com/Jameco/Products/ProdDS/2304999UsersManual.pdf),
  [Scribd](https://www.scribd.com/document/1012736837/Xgpro-user-Guide)
- [XGecu T48 support list](http://www.xgecu.com/MiniPro/T48_List.txt)
- [EEVblog — XGecu T48 ISP programming thread](https://www.eevblog.com/forum/testgear/xgecu-t48-isp-programming/)
- UI strings from the installed `Xgpro.exe`, and our wire captures
  documented in [`PROTOCOL.md`](PROTOCOL.md) §33–§34.
