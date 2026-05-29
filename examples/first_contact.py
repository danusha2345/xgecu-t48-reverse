#!/usr/bin/env python3
"""
first_contact.py — zero-risk first session against a freshly-arrived XGecu T48.

Run this the moment the T48 is plugged in — BEFORE inserting any chip and
WITHOUT the (separate) eMMC-ISP adapter. It exercises only identify / read-back
opcodes that apply NO programming voltage to the ZIF socket, and it logs every
USB transfer to a file so the session becomes ground truth for docs/PROTOCOL.md.

Each step is independent and non-fatal: one failing call does not stop the rest,
so even a partial run tells you which opcodes the firmware answers.

Steps (reply formats confirmed live — see docs/PROTOCOL.md §31):
  1. connect             — open a466:0a53
  2. identify_programmer — 8 zero bytes -> 63-byte info; byte[6] = model,
                           then NUL-terminated build date + serial
  3. measure_voltages    — read back idle rail voltages (no chip required)
  4. request_status      — 32-byte status block + OVC bit (may need a session;
                           treated as best-effort)
  5. read_pins           — 16-byte block; reply[8..14] = 6-byte (48-pin) bitmask

It deliberately NEVER calls begin_transaction() / init_emmc() / bulk_* — those
drive voltage and start an eMMC session, which needs the crypto adapter + a chip.

Usage:
    python3 first_contact.py                 # logs to ./t48_first_contact.log
    python3 first_contact.py --log my.log
"""
import argparse
import sys

from t48_emmc import T48Emmc, VID, PID


def _hexblock(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hexs:<{width*3}}  {asci}")
    return "\n".join(lines)


def step(label: str, fn):
    """Run one probe step, print result or error; never raise."""
    print(f"\n[*] {label}")
    try:
        return fn()
    except Exception as e:
        print(f"    [--] {type(e).__name__}: {e}")
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="t48_first_contact.log",
                    help="USB transfer log file (default: ./t48_first_contact.log)")
    args = ap.parse_args()

    print("== XGecu T48 — safe first-contact probe ==")
    print(f"   target {VID:04x}:{PID:04x}   transfer log -> {args.log}")
    print("   NOTE: no chip needed, no programming voltage applied, "
          "no eMMC session started.")

    dev = T48Emmc(log_path=args.log)

    if step("connect()", dev.connect) is None and dev.dev is None:
        print("\n[!] Could not open the T48. Check cabling / udev permissions "
              "(run as root or add a udev rule for a466:0a53).")
        return 1

    info = step("identify_programmer()  (8 zero bytes -> 63-byte info)",
                dev.identify_programmer)
    if info:
        print(_hexblock(info))
        if len(info) > 6:
            model = info[6]
            name = {0x05: "TL866II+", 0x06: "T56", 0x07: "T48", 0x08: "T76"}.get(model, "?")
            print(f"    model byte[6] = 0x{model:02x} ({name})")
        # firmware version — Xgpro shows "Ver XX.YY.ZZ" = bytes [0].[1].[4]
        # decimal (byte[4] is the build number; confirmed against Xgpro UI).
        if len(info) > 4:
            print(f"    firmware ver   = {info[0]:02d}.{info[1]:02d}.{info[4]:02d}"
                  f"   (byte[4]=0x{info[4]:02x}={info[4]} build)")
        # NUL-terminated build date right after the 8-byte header
        build = info[8:].split(b"\x00", 1)[0].decode("latin1", "replace")
        print(f"    firmware build = {build!r}")
        # trailing 16-bit word is a live ADC-like sample, NOT a fw version (§31.1)
        if len(info) >= 7:
            word = info[-7] | (info[-6] << 8)
            print(f"    trailing word  = 0x{word:04x} (dynamic sample, not a fw version)")

    volts = step("measure_voltages()  (idle rails)", dev.measure_voltages)
    if volts:
        for k, v in volts.items():
            print(f"    {k:<6} = {v:6.3f} V")

    status = step("request_status()  (best-effort without a session)",
                  dev.request_status)
    if status:
        print(_hexblock(status))
        if len(status) > 12:
            print(f"    OVC bit (byte[12] & 1) = {status[12] & 1}")

    pins = step("read_pins()  (16-byte block; reply[8..14] = 48-pin bitmask)", dev.read_pins)
    if pins:
        print(_hexblock(pins))

    dev.close()
    print(f"\n[OK] Probe complete. Full transfer trace saved to {args.log}")
    print("     Diff that log against docs/PROTOCOL.md to validate the wire "
          "format (reply sizes, model byte, status layout).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
