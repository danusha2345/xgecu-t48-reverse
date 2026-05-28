#!/usr/bin/env python3
"""
t48_emmc.py — каркас для своего ПО под XGecu T48, специализация на eMMC ISP.

Статус: ДРАФТ. Сделано до получения железа на основе реверса Xgpro.exe (см. REVERSE_NOTES.md).
К приезду T48 нужно:
 1. Запустить connect() — должно открыться устройство VID:PID a466:0a53.
 2. Сравнить ответы device на send_*_cmd() с теми, что мы предсказываем.
 3. Зачистить TODO-места по результатам USB-дампа.

Зависимости: pip install pyusb  (libusb-1.0 уже в системе)
"""
import struct
import time
import random
from typing import Optional

try:
    import usb.core
    import usb.util
except ImportError:
    raise SystemExit("pip install pyusb — модуль не установлен")

# ============================================================
# USB identification
# ============================================================
VID = 0xA466
PID = 0x0A53

# Endpoint pipes (определены из реверса 0x4dc380/0x4dc300):
EP1_OUT = 0x01       # commands + bulk-write setup
EP1_IN  = 0x81       # responses + bulk-read data (16B header + N*512B)
EP2_OUT = 0x02       # bulk write data (RPMB frames / CMD25)
# EP2_IN — не наблюдается в реверсе Xgpro

# ============================================================
# T48 protocol opcodes (унифицированная таблица)
# Источники:
#   - minipro/src/t48.c (классические опкоды 0x02..0x3F)
#   - реверс Xgpro.exe (eMMC расширение: 0x08, 0x14, 0x21, 0x27)
# ============================================================
class TopOp:
    """Top-opcode = byte[0] любого пакета EP1."""
    # Классика (из minipro/src/t48.c)
    NAND_INIT      = 0x02
    BEGIN_TRANS    = 0x03
    END_TRANS      = 0x04
    READID         = 0x05   # identify (используется и в eMMC init)
    READ_USER      = 0x06   # read user/config zone (используется и в eMMC init)
    READ_CFG       = 0x08   # см. также: в eMMC = long-recv обёртка
    WRITE_CFG      = 0x09
    READ_DATA      = 0x10
    WRITE_DATA     = 0x11
    SET_VCC_VOLTAGE= 0x1B
    SET_VPP_VOLTAGE= 0x1C
    REQUEST_STATUS = 0x39
    RESET          = 0x3F
    # eMMC-расширение (только Xgpro)
    EMMC_BULK_WRITE_SETUP = 0x14   # 16-байт setup перед N×512 EP2 OUT
    EMMC_INIT_SELECT      = 0x21   # init/select algorithm для eMMC
    EMMC_LONG_RECV        = 0x08   # обёртка для запросов с большим recv
    EMMC_SUBCMD           = 0x27   # диспетчер eMMC sub-команд (byte[1]=sub)

class EmmcSubOp:
    """Sub-opcode = byte[1] под top-opcode 0x27."""
    SWITCH          = 0x46   # CMD6 SWITCH (arg = BE-encoded JEDEC argument)
    STOP_AND_STATUS = 0x4C   # CMD12 STOP + CMD13 SEND_STATUS
    COMMIT          = 0x4D   # finalize (password/RPMB)
    DATA_BLOCK_512  = 0x50   # 512-байт data transfer (CMD24/OTP/RPMB data)
    SET_BLOCK_COUNT = 0x57   # CMD23 SET_BLOCK_COUNT (arg=count, обычно 1)
    READ_WGP_TABLE  = 0x5D   # read Write-Group Protection table

class LongRecvSubOp:
    """Sub-opcode = byte[1] под top-opcode 0x08."""
    READ_BLOCK_512 = 0x48    # CMD8 SEND_EXT_CSD / CMD17 READ_SINGLE_BLOCK (recv 512 байт)


# ============================================================
# JEDEC eMMC константы
# ============================================================
class Ecsd:
    """Индексы ECSD-полей (EXT_CSD), важных для нашего use-case."""
    HS_TIMING        = 0xAF   # 175 — переключение режима скорости
    PARTITION_CONFIG = 0xB3   # 179 — выбор активного раздела
    BUS_WIDTH        = 0xB7   # 183
    BOOT_BUS_WIDTH   = 0xB1   # 177
    USER_WP          = 0xAA   # 170
    BOOT_WP          = 0xAD   # 173

class PartAccess:
    """Биты [2:0] PARTITION_CONFIG — выбор раздела для CMD17/18/24/25."""
    USER  = 0b000
    BOOT1 = 0b001
    BOOT2 = 0b010
    RPMB  = 0b011
    GPP1  = 0b100
    GPP2  = 0b101
    GPP3  = 0b110
    GPP4  = 0b111

class SwitchAccess:
    """Access mode байта CMD6 SWITCH argument."""
    CMD_SET    = 0x00
    SET_BITS   = 0x01
    CLEAR_BITS = 0x02
    WRITE_BYTE = 0x03

def make_switch_arg(access: int, index: int, value: int, cmd_set: int = 0) -> int:
    """
    Упаковать аргумент для opcode 0x46 (CMD6 SWITCH).
    DWORD-значение, в котором старший байт = Access, как и в JEDEC CMD6 argument.
    Подтверждено реверсом: 0x01B30300 = SET_BITS, PARTITION_CONFIG (0xB3), Value 0x03 = RPMB.
    При упаковке в LE-память даст байты [00, 03, B3, 01] — то, что Xgpro кладёт в [ebp-12008].
    """
    return ((access & 0xFF) << 24) | ((index & 0xFF) << 16) | ((value & 0xFF) << 8) | (cmd_set & 0xFF)


# ============================================================
# Пакетные структуры
# ============================================================
def pack_cmd_A(opcode: int, arg: int) -> bytes:
    """
    Формат A: 8-байтный command-пакет EP1, magic 0x27.
    Используется через wrapper 0x492f30 в Xgpro.
    """
    return struct.pack('<BBHI', 0x27, opcode & 0xFF, 0x0000, arg & 0xFFFFFFFF)

def pack_cmd_B(opcode: int, length: int, arg: int) -> bytes:
    """
    Формат B: 8-байтный command-пакет EP1, magic 0x08.
    Используется через wrapper 0x492900 — для запросов с большим recv-ответом (CMD8 SEND_EXT_CSD).
    """
    return struct.pack('<BBHI', 0x08, opcode & 0xFF, length & 0xFFFF, arg & 0xFFFFFFFF)

def pack_bulk_read_setup(count: int) -> bytes:
    """
    Формат D: 16-байтный setup-пакет для bulk-чтения. Magic в bytes[0..4] = 0x02000015.
    Ответ ожидается на EP1 IN: 16 байт header + count*512 байт.
    """
    return (struct.pack('<I', 0x02000015)
          + struct.pack('<I', 0)
          + struct.pack('<HH', count & 0xFFFF, 0x0200)
          + struct.pack('<H', 0)
          + b'\x00\x00')

def pack_bulk_write_setup(opcode: int, count: int, block_addr: int) -> bytes:
    """
    Формат C-setup: 16-байтный пакет на EP1 перед bulk-write на EP2.
    Magic 0x14 (из дизасма 0x492670). TODO: уточнить остальные поля по дампу.
    """
    return (struct.pack('<BBHI', 0x14, opcode & 0xFF, count & 0xFFFF, block_addr & 0xFFFFFFFF)
          + struct.pack('<HHHH', 0, 0, 0, 0))

def build_rpmb_frame(req: int, address: int, block_count: int, write_counter: int,
                     data: bytes = b'\x00'*256, key_mac: bytes = b'\x00'*32,
                     nonce: Optional[bytes] = None) -> bytes:
    """
    Сборка 512-байтной JEDEC RPMB frame для отправки на EP2.
    Структура подтверждена реверсом wrapper'а 0x492670.

    req: код запроса (0x0001=program_key, 0x0002=read_wc, 0x0003=auth_data_write, 0x0004=auth_data_read, 0x0005=read_result)
    """
    if nonce is None:
        nonce = bytes(random.randint(0, 255) for _ in range(16))
    assert len(data) == 256
    assert len(key_mac) == 32
    assert len(nonce) == 16

    frame = bytearray(512)
    # [0x000..0x0C4] stuff bytes — нули
    frame[0x0C4:0x0E4] = key_mac
    frame[0x0E4:0x1E4] = data
    frame[0x1E4:0x1F4] = nonce
    struct.pack_into('>I', frame, 0x1F4, write_counter)        # BE counter
    struct.pack_into('<H', frame, 0x1F8, address & 0xFFFF)
    struct.pack_into('<H', frame, 0x1FA, block_count & 0xFFFF)
    struct.pack_into('<H', frame, 0x1FC, 0)                     # result
    struct.pack_into('<H', frame, 0x1FE, req & 0xFFFF)          # request/response
    return bytes(frame)


# ============================================================
# Высокоуровневые операции eMMC (черновики)
# ============================================================
class T48Emmc:
    def __init__(self):
        self.dev = None
        self.read_timeout_ms = 5000

    def connect(self) -> None:
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise RuntimeError(f"XGecu T48 не найден (VID={VID:04x} PID={PID:04x})")
        # На Linux WinUSB-устройства открываются через libusb напрямую.
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        print(f"[+] T48 открыт: {self.dev}")

    def close(self) -> None:
        if self.dev:
            try: usb.util.release_interface(self.dev, 0)
            except Exception: pass
            self.dev = None

    # ---- raw EP1 ----
    def ep1_send(self, data: bytes) -> int:
        return self.dev.write(EP1_OUT, data, timeout=self.read_timeout_ms)
    def ep1_recv(self, n: int) -> bytes:
        return bytes(self.dev.read(EP1_IN, n, timeout=self.read_timeout_ms))
    def ep2_send(self, data: bytes) -> int:
        return self.dev.write(EP2_OUT, data, timeout=self.read_timeout_ms)

    # ---- команды управления ----
    def switch_partition(self, partition_access: int) -> bytes:
        """CMD6 SWITCH — переключить активный раздел (BOOT1/BOOT2/RPMB/USER/GPP)."""
        arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, partition_access & 0x07)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)  # TODO: точный размер ответа уточнить по дампу

    def restore_user_access(self) -> bytes:
        """Сбросить PARTITION_ACCESS (биты [2:0]) в 000 — вернуться к USER."""
        arg = make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)

    def set_hs200(self) -> bytes:
        """CMD6: HS_TIMING = 0x01 (HS-200)."""
        arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)

    def read_ecsd(self) -> bytes:
        """CMD8 SEND_EXT_CSD — 512 байт ECSD."""
        self.ep1_send(pack_cmd_B(LongRecvSubOp.READ_BLOCK_512, 0x200, 0))
        # TODO: уточнить — приходит ли 512 байт сразу на EP1 IN, или 512+8 с header
        return self.ep1_recv(0x200)

    def set_block_count(self, n: int) -> bytes:
        """CMD23 SET_BLOCK_COUNT."""
        self.ep1_send(pack_cmd_A(EmmcSubOp.SET_BLOCK_COUNT, n))
        return self.ep1_recv(8)

    def stop_and_status(self) -> bytes:
        """CMD12 STOP + CMD13 SEND_STATUS."""
        self.ep1_send(pack_cmd_A(EmmcSubOp.STOP_AND_STATUS, 0))
        return self.ep1_recv(8)

    # ---- bulk read (USER/BOOT через CMD18) ----
    def bulk_read(self, count_sectors: int) -> bytes:
        """
        Bulk-read через формат D: setup на EP1 OUT + получение на EP1 IN.
        TODO: handshake перед — возможно нужен SET_BLOCK_COUNT и/или address-set.
        """
        self.ep1_send(pack_bulk_read_setup(count_sectors))
        return self.ep1_recv(16 + count_sectors * 512)

    # ---- bulk write (USER/BOOT/RPMB) ----
    def bulk_write(self, opcode: int, count_sectors: int, block_addr: int, payload: bytes) -> int:
        """
        Bulk-write через формат C: 16-байт setup на EP1 + N×512 на EP2.
        Для RPMB payload должен быть набором RPMB frames (build_rpmb_frame).
        """
        assert len(payload) == count_sectors * 512
        self.ep1_send(pack_bulk_write_setup(opcode, count_sectors, block_addr))
        return self.ep2_send(payload)


# ============================================================
# Sanity-чек при запуске
# ============================================================
if __name__ == "__main__":
    import sys
    # Не пытаемся реально слать команды — только проверка наличия устройства
    print("== Проверка структур пакетов (offline) ==")
    print(f"  cmd_A(SWITCH→RPMB)        = {pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, PartAccess.RPMB)).hex()}")
    print(f"  cmd_A(SWITCH→USER restore)= {pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)).hex()}")
    print(f"  cmd_A(SWITCH→HS200)       = {pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)).hex()}")
    print(f"  cmd_B(read ECSD 512)      = {pack_cmd_B(LongRecvSubOp.READ_BLOCK_512, 0x200, 0).hex()}")
    print(f"  bulk_read_setup(1 sector) = {pack_bulk_read_setup(1).hex()}")

    # Verify expected values from Xgpro reverse
    rpmb_arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, PartAccess.RPMB)
    assert rpmb_arg == 0x01B30300, f"RPMB switch arg mismatch: 0x{rpmb_arg:08x} vs 0x01B30300"
    user_arg = make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)
    assert user_arg == 0x02B30700, f"USER switch arg mismatch: 0x{user_arg:08x} vs 0x02B30700"
    hs200_arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)
    assert hs200_arg == 0x01AF0100, f"HS200 switch arg mismatch: 0x{hs200_arg:08x} vs 0x01AF0100"
    print("\n[OK] Все три расшифрованные команды сходятся с реверсом Xgpro.exe.")

    # Попытка подключения (требует T48)
    if "--connect" in sys.argv:
        emmc = T48Emmc()
        try:
            emmc.connect()
            print("[OK] T48 обнаружен")
        except Exception as e:
            print(f"[--] T48 не подключён: {e}")
        finally:
            emmc.close()
