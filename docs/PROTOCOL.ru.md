# XGecu T48 — заметки по реверсу протокола (eMMC)

> 🇬🇧 In English: [PROTOCOL.md](PROTOCOL.md)
>
> Это параллельная русская локализация. При расхождениях источник
> истины — `PROTOCOL.md`.

**Цель:** написать своё ПО на Linux для чтения/записи eMMC через программатор XGecu T48 в режиме ISP. Этот документ собирает результаты реверса.

**Источники истины:**
- `xgecu/Xgpro.exe` — официальный софт (PE32, 32-бит x86, WinUSB).
- `xgecu/algorithm/*.alg` — FPGA-битстримы + параметры алгоритмов.
- `xgecu/InfoIC2Plus.dll` — БД чипов (выгружена в `emmc_chips_t48.json`).
- minipro 0.7.4 (GPL): `/path/to/minipro/`, `src/t48.c` — открытая реверс-реализация транспорта T48.

---

## 1. USB-идентификация устройства

Из `xgecu/drv/Xgprowinusb.inf`:
- **VID/PID:** `0xA466 / 0x0A53`
- Класс: WinUSB (vendor-specific bulk)
- DeviceInterfaceGUID: `{E7E8BA13-2A81-446E-A11E-72398FBDA82F}`
- Производитель: «Haikou Xingong Electronic Co,Ltd»

Linux: открывается напрямую через libusb (`pyusb`/`libusb-1.0`).

## 2. Endpoint-схема

Из анализа `Xgpro.exe` (вызовы `WinUsb_WritePipe` / `WinUsb_ReadPipe`):

| EP | Что идёт | Размер пакета |
|----|---|---|
| **EP1** | Команды/конфиг/статус | 8 или 16 байт (фиксированные структуры) |
| **EP2** | Bulk-данные eMMC | `N × 512` байт (sector-aligned) |

Статистика call-сайтов: `WinUsb_WritePipe` = 36, `WinUsb_ReadPipe` = 70, `WinUsb_Initialize` = 1.

## 3. Транспорт классических чипов (открыт minipro)

Источник — `minipro/src/t48.c`. Опкоды 0x02–0x3F:

```c
#define T48_NAND_INIT            0x02
#define T48_BEGIN_TRANS          0x03   // 64-байтный init-пакет: protocol_id, voltages, clock, sizes
#define T48_END_TRANS            0x04
#define T48_READID               0x05
#define T48_READ_USER            0x06
#define T48_WRITE_USER           0x07
#define T48_READ_CFG             0x08
#define T48_WRITE_CFG            0x09
#define T48_WRITE_USER_DATA      0x0A
#define T48_READ_USER_DATA       0x0B
#define T48_WRITE_CODE           0x0C
#define T48_READ_CODE            0x0D
#define T48_ERASE                0x0E
#define T48_TEST_RAM             0x0F
#define T48_READ_DATA            0x10
#define T48_WRITE_DATA           0x11
#define T48_WRITE_LOCK           0x14
#define T48_READ_LOCK            0x15
#define T48_READ_CALIBRATION     0x16
#define T48_PROTECT_OFF          0x18
#define T48_PROTECT_ON           0x19
#define T48_SET_VCC_VOLTAGE      0x1B
#define T48_SET_VPP_VOLTAGE      0x1C
#define T48_READ_JEDEC           0x1D
#define T48_WRITE_JEDEC          0x1E
#define T48_LOGIC_IC_TEST_VECTOR 0x28
#define T48_RESET_PIN_DRIVERS    0x2D
#define T48_SET_VCC_PIN          0x2E
#define T48_SET_VPP_PIN          0x2F
#define T48_SET_GND_PIN          0x30
#define T48_SET_PULLUPS          0x31
#define T48_SET_PULLDOWNS        0x32
#define T48_MEASURE_VOLTAGES     0x33
#define T48_READ_PINS            0x35
#define T48_SET_OUT              0x36
#define T48_AUTODETECT           0x37
#define T48_UNLOCK_TSOP48        0x38
#define T48_REQUEST_STATUS       0x39
#define T48_BOOTLOADER_WRITE     0x3B
#define T48_BOOTLOADER_ERASE     0x3C
#define T48_SWITCH               0x3D
#define T48_RESET                0x3F
```

## 4. eMMC-часть протокола (опкоды 0x40+, не реверсирована minipro)

**Главная функция-обёртка `0x492f30` в Xgpro.exe.** Зовётся 101 раз. Сигнатура (по дизасму):
```c
int sub_492f30(handle ebx, byte opcode, dword arg3, ? esi);
```

Внутри строит пакет на стеке начиная с magic-байта `0x27`, опкода и параметров. Первые 8 байт пакета:
```
offset 0: 0x27       // magic (постоянный)
offset 1: opcode     // байт из arg2
offset 2: 0x0000     // u16, обнуляется
offset 4: arg3       // dword (LE)
```

(Полный размер пакета и роль 4-го аргумента ещё уточняются — см. ниже.)

### Найденные eMMC-опкоды (частотный анализ 101 вызова)

| Opcode | dec | Вызовов | Гипотеза |
|---|---|---|---|
| **0x46** | 70 | 59 | Базовая операция eMMC (CMDx + параметры) |
| 0x50 | 80 | 15 | (TBD — часто; возможно, чтение статуса/конфигурации) |
| 0x57 | 87 | 4 | (TBD) |
| 0x4D | 77 | 4 | (TBD) |
| 0x4C | 76 | 1 | (TBD — редкая инициализация?) |
| 0x5D | 93 | 1 | (TBD) |
| 0x5C | 92 | 1 | (TBD) |

Опкоды находятся ВЫШЕ зоны 0x02-0x3F, обработанной minipro → это и есть «дельта» под eMMC.

### Семантические точки в коде (xref'ы строк ошибок)

| JEDEC CMD | Назначение | Строка-маркер | VA xref |
|---|---|---|---|
| CMD0/1/2/3 | EMMC init | `EMMC Init ERROR` | 0x4afad5 |
| CMD12 | STOP_TRANSMISSION | ` -- CMD12` | 0x4ad042 |
| CMD13 | SEND_STATUS | `Device write error :CMD13` | 0x4acfce, 0x4ad4d8 |
| CMD18 | READ_MULTIPLE_BLOCK | `ReadDevice Error : CMD18` | 0x49dc96, 0x4a9e57 |
| CMD25 | WRITE_MULTIPLE_BLOCK | `ReadDevice Error : CMD25` | 0x49dcbd, 0x4a9e5e |
| watchdog | bulk-read timeout | `EMMC stops responding` | 0x4a8b0b |

Из каждой точки можно проследить ближайший `call 0x492f30` и извлечь использованный опкод+параметры → построить таблицу «JEDEC CMD → T48 USB-пакет».

## 5. Формат файла `.alg` (битстрим FPGA)

Полностью разобран и верифицирован (см. сессию 2026-05-27). Кратко:

```
0x000  : имя семейства, ASCII \0-terminated
0x000..0x220 : zero-padded заголовок (у некоторых семейств в нём sparse-параметры)
0x220  : u32 LE = размер распакованного битстрима = 340604 (КОНСТАНТА → Xilinx Spartan-6 ~LX9)
0x224  : u32 LE = CRC32 сжатых данных = (zlib.crc32(comp) XOR 0xFFFFFFFF)
0x228  : сжатые данные — zero-RLE по u16:
            val=u16; если val≠0 → пишем val;
                     если val=0 → len=u16, пишем len нулевых слов.
```

Распакованные данные содержат стандартное начало Xilinx-битстрима: 16×0xFF преамбула + sync `AA 99 55 66`.

### Связь `variant` ↔ файл `.alg` (через старший байт variant)

| variant | name pattern | `.alg` файл | Применение |
|---|---|---|---|
| 0x53xx | `_8Bit @BGA153` | EMMC_53_{18,33}.alg | BGA сокет 8-bit |
| 0x54xx | `_4Bit @BGA153` | EMMC_54_{18,33}.alg | BGA сокет 4-bit |
| 0x51xx | `_1Bit @BGA153` | EMMC_51_{18,33}.alg | BGA сокет 1-bit |
| **0x44xx** | `(ISP) _4Bit` | **EMMC_44_{18,33}.alg** | **ISP 4-bit (наш кейс)** |
| **0x41xx** | `(ISP) _1Bit` | **EMMC_41_{18,33}.alg** | **ISP 1-bit (наш базовый)** |

Суффикс `_18`/`_33` = `VCCQ` 1.8В / 3.3В.

## 6. БД чипов

Выгружена через `dumpic/dump-infoic2plus-dll.exe` (wine):
- 173 производителя, 34 352 чипа всего
- **4 796 eMMC** (тип 7), все с `protocol_id = 0x31`
- Полный отфильтрованный список eMMC: `emmc_chips_t48.json` (2.4 МБ)

## 7. Точная структура пакета EP1 (8 байт)

Подтверждено по дизасму `0x492f30`:

```c
// Сигнатура: int sub_492f30(handle, byte opcode, dword arg3, ptr arg4)
struct EP1_Command {
    uint8_t  magic;    // = 0x27  (hardcoded, "'")
    uint8_t  opcode;   // 0x46/0x4C/0x4D/0x50/0x57/0x5C/0x5D
    uint16_t pad;      // = 0x0000
    uint32_t arg3;     // 4-байтный параметр (LE)
};
// → отправляется 8 байт на EP1 через sub_4dc380(handle, buf, 8)
```

4-й аргумент `esi/arg4` — указатель/счётчик (out param для статуса), НЕ часть пакета. После send идёт recv ответа через `sub_4dc300`.

## 8. Иерархия USB-обёрток

```
Уровень 3 (семантические команды eMMC):
  0x4af370  — eMMC init (вызывает 0x492f30 дважды с opcode 0x46)
  0x4acee0  — CMD12 + CMD13 (opcode 0x4C)
  0x4ad240  — CMD13 alt (opcode 0x57, 0x50)
  0x49d910  — CMD18/25 BGA-сокет
  0x4a98f0  — CMD18/25 ISP (← наш кейс! через 0x492670)
  0x4a8110  — bulk-read с watchdog

Уровень 2 (USB-command builders):
  0x492f30  — 8-байтная команда EP1 (101 вызов; opcodes 0x46/0x4C/0x4D/0x50/0x57/0x5C/0x5D)
  0x492670  — bulk: 16-байт setup EP1 + N×512 на EP2  ← главный для eMMC данных
  0x492590  — 64-байтная команда (вызывается из ISP-варианта; формат пакета TBD)
  0x492900  — bulk-read (~512 байт)
  0x4dc070  — общий wrapper (10 WritePipe-вызовов)

Уровень 1 (raw USB):
  0x4dc380  — sub_send(handle, buf, len) → WinUsb_WritePipe(EP1)
  0x4dc300  — sub_recv(handle, buf, len) → WinUsb_ReadPipe (EP1)
  0x633e6c  — stub WinUsb_WritePipe (вызывается с EP=1 или EP=2)
  0x633e66  — stub WinUsb_ReadPipe
```

## 9. Конкретный маппинг JEDEC CMD → пакет (по разобранным точкам)

| JEDEC | Функция | Wrapper | Opcode | arg3 |
|---|---|---|---|---|
| init (CMD0/1/?) | 0x4af370 | `0x492f30` | **0x46** | `0x02FFFF00` затем `0x01AF0100` (два пакета подряд) |
| CMD12 + CMD13 | 0x4acee0 | `0x492f30` | **0x4C** | `0` |
| CMD13 (alt) | 0x4ad240 | `0x492f30` | **0x57**, **0x50** | `1`, `eax` (динамика) |
| CMD18/25 ISP | 0x4a98f0 | `0x492670` (bulk) + `0x492590` (?64б) | — | edx/eax/edi (адреса буферов) |
| EMMC init also | 0x4af370 | прямые `0x4dc380/0x4dc300` | (без обёртки) | 8-байт send + 8/24/32-байт recv (видимо, чтение статуса FPGA) |

**Гипотезы по семантике opcode'ов** (нужно подтвердить):
- `0x46` (59 вызовов) — самая частая: «отправить eMMC-CMD»; arg3 = упакованные данные команды (CMD-байт + 3 байта аргумента?). В init `0x02FFFF00` мог бы быть «CMD2 + ALL_SEND_CID stuff», `0x01AF0100` — «CMD1 + OCR».
- `0x4C` — «stop+status» (CMD12+CMD13 в одной функции).
- `0x57`, `0x50` — варианты статус-запроса с динамическими параметрами.
- `0x4D`, `0x5C`, `0x5D` — редкие (по 1-4 вызова): партиция/режим/калибровка.

## 9b. Точная сигнатура низкоуровневых send/recv (подтверждено дизасмом)

```c
// 0x4dc380 — sub_send(handle, buf, len)
//   → WinUsb_WritePipe(h, PipeID=1, buf, len, &transferred, NULL)
// EP1 OUT (= pipe ID 1)

// 0x4dc300 — sub_recv(handle, buf, len)  
//   → WinUsb_ReadPipe(h, PipeID=0x81, buf, len, &transferred, NULL)
// EP1 IN (= pipe ID 0x81)

// EP1 двунаправленный: команды + статусные ответы.
// Для bulk-данных eMMC переключается на EP2 (pipe ID = 2 OUT, 0x82 IN).
```

## 9b-bis. УТОЧНЕНИЕ АРХИТЕКТУРЫ (важно): top-opcode + sub-opcode

То, что в предыдущих разделах называлось «magic 0x27 + opcode» — это на самом деле **`top-opcode = 0x27` + `sub-opcode`** в общей схеме T48 protocol. Иерархия плоская:

```
Любой command-пакет EP1 = [byte 0: top-opcode] [byte 1..7: параметры/sub-opcode]
```

**Top-opcodes объединённой таблицы T48 (для T48 и eMMC):**

| Top-opcode | Источник | Назначение | byte[1..7] |
|---|---|---|---|
| `0x00` | Xgpro (live §31) | **device identify** — дата сборки + серийник + версия | нулевой 8-байт запрос → 63-байт ответ |
| `0x02` | minipro (классика) | NAND_INIT | — |
| `0x03` | minipro (классика) | **BEGIN_TRANSACTION** (init сессии: protocol_id, voltages, clock) | 64-байт пакет |
| `0x04` | minipro | END_TRANSACTION | — |
| **`0x05`** | minipro + Xgpro | **READID** — identify chip | 2-байт param (видим в init eMMC, recv 32б) |
| **`0x06`** | minipro + Xgpro | **READ_USER** — config зона | recv 24б в init eMMC |
| `0x07..0x1F` | minipro | классические операции | — |
| **`0x08`** | Xgpro NEW (eMMC) | **«long-recv» обёртка** | byte 1 = sub-opcode (`0x48`=read 512б) + length + addr |
| **`0x14`** | Xgpro NEW (eMMC) | **bulk-write setup** перед EP2 OUT | sub-opcode + count + block_addr |
| **`0x21`** | Xgpro NEW (eMMC) | init/select-algorithm для eMMC | 1-байт параметр из конфига |
| **`0x27`** | Xgpro NEW (eMMC) | **eMMC sub-command dispatcher** | sub-opcode + arg32 (см. ниже) |
| `0x39` | minipro | REQUEST_STATUS | — |
| `0x3F` | minipro | RESET | — |

**Sub-opcodes под top-opcode `0x27` (eMMC subcommands):**

| Sub-op | Семантика | arg32 |
|---|---|---|
| `0x46` | **CMD6 SWITCH** | BE-encoded JEDEC: `[Access][Index][Value][CmdSet]` |
| `0x4C` | **CMD12 STOP + CMD13 STATUS** | `0` |
| `0x4D` | **commit / finalize FPGA** (password/RPMB) | — |
| `0x50` | **data transfer 512 байт** (CMD24/OTP/RPMB) | `0x200` |
| `0x57` | **CMD23 SET_BLOCK_COUNT** | количество блоков (обычно `1`) |
| `0x5C` | TBD (1 вызов) | — |
| `0x5D` | **Read WGP table** (write group protection) | — |

**Sub-opcode под top-opcode `0x08`:**

| Sub-op | Семантика |
|---|---|
| `0x48` | **CMD8 SEND_EXT_CSD / CMD17 READ_SINGLE_BLOCK** (recv 512 байт) |

## 9b-tris. Init-последовательность eMMC

Реверс функции `0x4af370` (eMMC init sub-этап, вызываемой после `BEGIN_TRANS`):

```
Шаг 1: top-opcode 0x21 + 1-байт параметр [из 0x7485d0]   → recv 8 байт
       (предположительно «select algorithm/variant» для eMMC)

Шаг 2: top-opcode 0x05 (READID) + 2-байт параметр [0x7a39cc]  → recv 32 байта
       (chip ID / OCR / CID)

Шаг 3: top-opcode 0x06 (READ_USER)                            → recv 24 байта
       (конфиг или CSD)

Шаг 4: top-opcode 0x27, sub 0x46 (CMD6 SetBits HS_TIMING=0x01)  → перевод в HS-200
Шаг 5: top-opcode 0x27, sub 0x46 (CMD6 ...)                     → ещё одна ECSD-настройка
```

Тонкость: `BEGIN_TRANSACTION` (0x03) с конкретным `protocol_id = 0x31 (IC2_ALG_EMMC)` и `variant` (например `0x4100` для ISP 1-bit) выдается ДО `0x4af370` из caller-функций. Структура `BEGIN_TRANS` пакета в minipro/src/t48.c — 64 байта (см. раздел 8 этого документа).

## 9c. Wrapper'ы 8-байтных команд (есть ДВА разных формата!)

### Формат A — opcode `0x27` magic (через `0x492f30`)
```c
struct EP1_Cmd_A {  // отправка + ожидание короткого ответа
    uint8_t  magic = 0x27;
    uint8_t  opcode;     // 0x46/0x4C/0x4D/0x50/0x57/0x5C/0x5D
    uint16_t pad = 0;
    uint32_t arg;
};
```
Применение: **управляющие команды** (CMD6 SWITCH, CMD13 STATUS, etc.)

### Формат B — opcode `0x08` magic (через `0x492900`)
```c
struct EP1_Cmd_B {  // отправка + ожидание большого ответа (через EP1 или EP2)
    uint8_t  magic = 0x08;
    uint8_t  opcode;     // 0x48 (?)
    uint16_t length;     // размер ожидаемых данных (например 0x200 = 512)
    uint32_t arg;        // адрес/параметр
};
```
Применение: **запросы с переменным ответом** (CMD8 SEND_EXT_CSD читает 512 байт)

### Формат C — bulk write через `0x492670`
```
EP1 setup (16 байт) + EP2 OUT (N×512 байт данных)
```
Применение: **CMD25 WRITE_MULTIPLE_BLOCK** (запись eMMC через ISP)

### Формат D — bulk read через `0x492590`
```
EP1 setup (16 байт, magic=0x02/0x15) + EP1 IN (16 байт header + N×512 байт данных)
```
Применение: **CMD18 READ_MULTIPLE_BLOCK** (чтение eMMC; данные приходят на EP1 IN с заголовком)

## 9d. КЛЮЧЕВОЕ ОТКРЫТИЕ: кодировка `arg` для opcode `0x46` = JEDEC CMD6 SWITCH в big-endian

`arg3` DWORD в LE-памяти, прочитанный как BE-байты, **точно соответствует аргументу JEDEC eMMC CMD6**:

```
arg3 (LE storage)    BE-байты           JEDEC CMD6 SWITCH аргумент
─────────────────    ────────────       ─────────────────────────────
                     [B3 B2 B1 B0]
                     Access | Index | Value | CmdSet
```

Где `Access` ∈ {01=Set-Bits, 02=Clear-Bits, 03=Write-Byte}, `Index` ∈ ECSD-индекс (0-255), `Value` — записываемое значение.

**Расшифрованные команды из реверса:**

| arg3 (LE) | BE-байты | JEDEC ECSD поле | Семантика |
|---|---|---|---|
| `0x01B30300` | `01 B3 03 00` | `[179] PARTITION_CONFIG`, Set-Bits, Value=`0x03` | **Switch to RPMB** |
| `0x02B30700` | `02 B3 07 00` | `[179] PARTITION_CONFIG`, Clear-Bits, Value=`0x07` | **Switch back to USER** |
| `0x01AF0100` | `01 AF 01 00` | `[175] HS_TIMING`, Set-Bits, Value=`0x01` | **Перевод в HS-200** (init) |
| `0x02FFFF00` | `02 FF FF 00` | ? | начальный reset (TBD) |

Это означает: **CMD6 SWITCH к любому разделу (BOOT1/BOOT2/RPMB/USER/GPP1-4) — это просто отправка пакета формата A с opcode=0x46 и arg3=BE-encoded JEDEC аргумент**.

Полная карта PARTITION_ACCESS (биты [2:0] PARTITION_CONFIG):
- `000` = USER (default)
- `001` = BOOT1
- `010` = BOOT2
- `011` = RPMB
- `100`..`111` = GPP1..GPP4

## 9e. Полная таблица опкодов eMMC

| Opcode | Wrapper | Семантика | Подтверждение |
|---|---|---|---|
| **0x46** | `0x492f30` (фмт A) | **CMD6 SWITCH** (BE-encoded JEDEC arg) | расшифровка arg3: SetBits/ClearBits + Index + Value |
| **0x48** | `0x492900` (фмт B) | **Read 512-byte block** (CMD8/CMD17, BOOT-страница) | вызывается 3 раза с size=0x200 в функции Read ECSD |
| **0x4C** | `0x492f30` (фмт A) | **CMD12 STOP + CMD13 STATUS** | строки " -- CMD12" / "CMD13" в той же функции |
| **0x4D** | `0x492f30` | Commit / finalize FPGA | контекст: "Set Password", "Password Reset", RPMB финализация |
| **0x50** | `0x492f30` | 512-байтный data transfer (CMD24 / OTP / CSD / RPMB-write) | в паре с 0x57; всегда arg3=0x200; контекст CSD/PWD/RPMB |
| **0x57** | `0x492f30` | **CMD23 SET_BLOCK_COUNT** (всегда arg3=1) | контекст: "Device write error : CMD23" во ВСЕХ 4 функциях |
| `0x5C` | `0x492f30` | TBD (1 вызов, нет якорных строк) | низкий приоритет |
| **0x5D** | `0x492f30` | Read Write Group Protection table | строка "No respond to read WGP protection table" |

## 9h. Расшифровка формата C — bulk write (0x492670 → EP2)

Внутри 0x492670 строится **JEDEC-совместимая RPMB frame** в 512-байтном буфере, затем шлётся на EP2. Точные смещения:

| Смещение | Размер | Назначение | Соответствует JEDEC RPMB |
|---|---|---|---|
| `0x000..0x0C4` | 196 | Stuff bytes | ✓ stuff bytes |
| `0x0C4..0x0E4` | 32 | Key/MAC (выбор из таблиц `0x79A690` или `0x7C8048`) | ✓ Authentication Key / MAC |
| `0x0E4..0x1E4` | 256 | Data | ✓ Data |
| `0x1E4..0x1F4` | 16 | Random Nonce (`rand()`, опционально) | ✓ Nonce |
| `0x1F4..0x1F8` | 4 BE | Write Counter | ✓ Write Counter |
| `0x1F8..0x1FA` | 2 | Address | ✓ Address |
| `0x1FA..0x1FC` | 2 | Block Count | ✓ Block Count |
| `0x1FC..0x1FE` | 2 | Result | ✓ Result |
| `0x1FE..0x200` | 2 | Req/Resp | ✓ Request/Response |

**Последовательность отправки:**
1. EP1 OUT: 16-байтный setup-пакет с magic `0x14` (length=0x10).
2. EP2 OUT (через `WinUsb_WritePipe(pipe=2)`): N×512 байт = RPMB frames.

Флаги `arg28/arg2C` управляют включением nonce/key, так что та же функция работает и для обычного CMD25 без RPMB-обвески.

## 9i. Расшифровка формата D — bulk read (0x492590 → EP1 IN)

```c
// 16-байтный setup-пакет, magic 0x02:
struct EP1_BulkRead_Setup {
    uint32_t magic_and_op = 0x02000015;   // bytes [15 00 00 02] LE — magic 0x02, op-byte 0x15
    uint32_t reserved = 0;
    uint16_t count;                       // число 512-байт блоков
    uint16_t block_size = 0x200;
    uint16_t padding = 0;
};
// → send 16 bytes on EP1 OUT (pipe=1)
// Затем:
// → recv (count * 512 + 16) bytes on EP1 IN (pipe=0x81) — bulk-данные с 16-байт header'ом
```

Интересно: EP2 IN, видимо, не используется (или используется в редких путях). **Все bulk-чтения идут через EP1 IN.** EP2 OUT — только для write-фреймов (RPMB/CMD25).

## 9f. Адресная карта буфера (из строк UI Xgpro)

```
BOOT1 last page : буфер 0x10000-0x13FFF (16 КБ), устройство 0x1FC50000-0x1FC53FFF
BOOT2 last page : буфер 0x30000-0x33FFF (16 КБ), устройство 0x1FC70000-0x1FC73FFF
```
(Примечание: адреса устройства зависят от ёмкости конкретной eMMC.)

## 9g. Поток операций для типичных задач (черновик)

### Чтение ECSD (512 байт)
```
0. (предположительно) begin_transaction подобно minipro:
   handshake/инициализация устройства, выбор protocol_id=0x31, variant (наприм. 0x4100 для ISP 1-bit)
1. eMMC init: CMD0 → CMD1 (OCR) → CMD2 (CID) → CMD3 → CMD7
   Реализовано в Xgpro через серию обращений к 0x4dc380/0x4dc300 + CMD6 SetBits HS_TIMING=1
2. EP1 cmd format-B: magic=0x08, opcode=0x48, length=0x200, arg=0
   → recv 512-byte ECSD
```

### Чтение BOOT1 (16 КБ)
```
1. CMD6 SWITCH: opcode=0x46, arg=encode(SetBits, PARTITION_CONFIG=0xB3, Value=0x01)  // Access=BOOT1
2. Цикл по блокам: EP1 cmd format-B opcode=0x48 length=0x200 arg=block_addr (или bulk-чтение через 0x492590)
3. CMD6 SWITCH назад: opcode=0x46, arg=encode(ClearBits, 0xB3, 0x07)  // вернуть к USER
```

### Чтение USER (bulk через ISP)
```
1. CMD18 setup через 0x492590 (16-byte EP1 setup) с числом блоков = N
2. Получение N×512 байт через EP1 IN (с 16-байтным header)
3. CMD12 STOP опционально (opcode 0x4C)
```

## 10. Открытые вопросы

- [ ] Точная семантика 7 опкодов (поможет дамп для верификации).
- [ ] Формат и размер пакета `0x492590` (видим только размер 0x40=64 байта).
- [ ] Формат ответа на EP1 (видны recv-размеры 8, 24, 32 — какие поля).
- [ ] Триггер EP2-чтения после CMD18 (как Xgpro узнаёт, что FPGA готов отдать данные).
- [ ] Релэй аутентификации фирменного eMMC-ISP адаптера (если ПК участвует).
- [ ] Полная таблица опкодов 0x40-0x60 (возможно, есть незадействованные в eMMC).

## 11. Ход проекта — итог по этой сессии

✅ minipro 0.7.4 собран, бинарь готов (`/path/to/minipro/minipro`)
✅ БД 4796 eMMC-чипов выгружена (`emmc_chips_t48.json`)
✅ Формат `.alg` разобран и верифицирован, есть распаковщик
✅ VID:PID, endpoint-схема, иерархия обёрток установлены
✅ Структура 8-байтной EP1-команды зафиксирована
✅ Список eMMC-опкодов извлечён, частично сопоставлен с JEDEC
⏳ Точная семантика opcode'ов (нужен USB-дамп для финальной валидации)
⏳ Bulk EP2 — формат setup-пакета и поток данных
⏳ Командный поток в самой ISP-функции (там есть свой формат 64-байт)

## 8. Адаптер с крипточипом

Адаптер «XGecu EMMC-ISP VER 1.00» содержит secure-auth IC (вероятно ATSHA204A-класс):
- Аутентифицируется к **прошивке T48**, не к ПК-софту.
- Для своего ПО ломать его НЕ нужно — пускаем команды как есть, прошивка сама ведёт диалог с адаптером.
- Если в USB-обмене обнаружится pass-through aуть-байтов — это просто релэй (без знания ключа).

---

## 19. Уточнения от Ghidra-декомпиляции

После импорта `Xgpro.exe` в Ghidra 12 и декомпиляции ключевых wrapper'ов
(которые в предыдущих разделах были выведены косвенно из ассемблера через
capstone) получены ТОЧНЫЕ подтверждения и важные уточнения.

### 19.1 `sub_4dc380` (raw EP1 send)

```c
void raw_send(handle, buf, len) {
    WinUsb_WritePipe(handle, /*PipeID=*/1, buf, len, &transferred, NULL);
}
```
Всегда pipe 1. Подтверждает `EP1_OUT = 0x01`.

### 19.2 `sub_4dc300` (raw EP1 recv)

```c
int raw_recv(handle, buf, len) {
    int chip_type = chip_type_table[slot * 0xEC];
    int actual_len = (chip_type == 6) ? len + 1 : len;   // NAND нужен +1 байт
    WinUsb_ReadPipe(handle, /*PipeID=*/0x81, buf, actual_len, ...);
}
```
Всегда pipe 0x81 (EP1 IN). Для NAND host запрашивает `len + 1` байт.

### 19.3 Format A — `FUN_00492f30` (top-opcode `0x27`)

Пакет 8 байт `[0x27][sub_op][u16 = 0][u32 arg LE]`. Send EP1 OUT, recv 8 байт
EP1 IN. Если `reply[1] != 0` → success.

### 19.4 Format B — `FUN_00492900` (top-opcode `0x08`) — **EP2 IN для eMMC!**

```c
void cmd_B(handle, byte sub_op, ushort length, dword arg, char* reply) {
    uint8_t pkt[8] = {0x08, sub_op, length&0xFF, length>>8, arg LE};
    raw_send(handle, pkt, 8);                                    // EP1 OUT
    int chip_type = ...;
    if (chip_type == 7 || chip_type == 8)
        WinUsb_ReadPipe(handle, 0x82, reply, length + 8, ...);   // EP2 IN!
    else
        raw_recv(handle, reply, length + 8);                     // EP1 IN
}
```

**Критическая поправка:** для eMMC ответ на Format B приходит на **EP2 IN
(pipe 0x82)**, а не на EP1 IN. Полный размер ответа = `length + 8`. Наш
Python-прототип `read_ecsd()` обновлён соответственно.

### 19.5 Format C — `FUN_00492670` (bulk-write eMMC) — **EP2 OUT**

16-байтный setup на EP1: `[0x14, sub_op, 0, 0, 0, 0, 0, 0, count_lo, count_hi, 0x00, 0x02, 0, 0, 0, 0]`.

Затем payload 512×count байт. ПО chip_type:
- chip_type == 7 (eMMC): `WinUsb_WritePipe(handle, /*pipe=*/2, payload, count*512)` — EP2 OUT
- chip_type == 8 (VGA): `WinUsb_WritePipe(handle, /*pipe=*/5, payload, count*512)` — **EP5 OUT (!)**
- иначе: 16 + 512 = 528 байт одним пакетом на EP1 OUT

Внутри 512-байт payload — JEDEC-RPMB трейлер в последних 12 байтах +
опциональные nonce и 32-байт ключ из таблицы `DAT_0079A690` или
`DAT_007C8048` (две RPMB-таблицы, выбор по `param_10`).

### 19.6 Format D — `FUN_00492590` (bulk-read setup)

```c
pkt = [0x02000015 LE, 0, count_lo, count_hi, 0x00 0x02, 0, 0, 0, 0]   // 16 байт
raw_send(handle, pkt, 16);
if (chip_type == 7 || chip_type == 8)
    FUN_004dbd50(handle, recv_buf, count * 512 + 16);   // ← отдельная функция
else
    raw_recv(handle, recv_buf, count * 512 + 16);       // EP1 IN
```

Для eMMC bulk-read идёт через **отдельную функцию `FUN_004dbd50`** —
скорее всего, она читает с EP2 IN (по аналогии с Format B). Точно
выяснить — следующий шаг декомпиляции.

### 19.7 `composite_EP1` — `FUN_004dc070` (мульти-пайповые транзакции)

Wrapper для передач, не вмещающихся на один endpoint. По chip_type:

- chip_type 6 (NAND): EP1 setup + EP1 data (split)
- chip_type 7 (eMMC): EP1 setup + **EP2 OUT** data
- большие передачи: EP1 + **EP2 + EP3 OUT** параллельно (async через
  `CreateEventA` + `WaitForSingleObject`)

То есть Xgpro **может полосовать (stripe)** один логический command на
EP1+EP2+EP3 одновременно для больших payload'ов. Не критично для нашего
eMMC ISP пути, но знание полезно.

### 19.8 eMMC init (`FUN_004af370`) — точные raw-пакеты

```c
// Шаг 1 — top-opcode 0x21:
buf[0] = 0x21;
buf[1] = DAT_007485d0;        // 1-байт параметр
raw_send(handle, buf, 8);
raw_recv(handle, reply, 8);

// Шаг 2 — top-opcode 0x05 (READID):
buf[0] = 0x05;
*(u16*)&buf[2] = DAT_007a39cc;
*(u32*)&buf[4] = 0;
raw_send(handle, buf, 8);
raw_recv(handle, reply, 0x20);  // 32 байта  ← chip ID / OCR / CID

// Шаг 3 — top-opcode 0x06 (READ_USER):
buf[0] = 6;
raw_send(handle, buf, 8);
raw_recv(handle, reply, 0x18);  // 24 байта  ← config / CSD
```

Success-проверка везде: `reply[1] != 0`.

### 19.9 Чтение EXT_CSD (`FUN_004a1130`) — полный поток

Функция Read ECSD делает **три подряд** Format B вызова с одинаковыми
параметрами:

```c
FUN_00492900(handle, 0x48, 0x200, 0, recv_buf);   // x3
```

Это, видимо, **тройное чтение для верификации** (сравнить три копии
EXT_CSD; если совпадают — данные надёжные). Стандартная защитная
практика для длинных ISP-линий.

### 19.10 Layout ответов init-команд

```
Ответ 8 байт на opcode 0x21 (INIT_EMMC):
  byte 1     : status (0 = OK)
  byte 4..8  : u32 = OCR register (стандарт JEDEC eMMC, raw)
               bit 30 = high-capacity flag
               bits [23:8] должны быть 0xFF8080 для 1.8V

Ответ 32 байта на opcode 0x05 (READID → CID):
  byte 1       : status
  byte 8..0x18 : 16 байт = CID register (128-bit unique chip ID)

Ответ 24 байта на opcode 0x06 (READ_USER → CSD):
  byte 1       : status
  byte 8..0x18 : 16 байт = CSD register (128-bit Card-Specific Data)
```

CID и CSD сохраняются в глобальный буфер `DAT_007a4034`: CID на offset 0,
CSD на offset 0x10. Высокоуровневый код читает их прямо оттуда.

### 19.11 `FUN_004dbd50` — bulk-read для eMMC, точно

```c
void bulk_read_emmc(handle, buf, size) {
    int chip_type = chip_type_table[slot * 0xEC];
    if (chip_type == 6)        raw_recv(handle, buf, size);        // NAND: EP1 IN
    else if (chip_type == 7 || chip_type == 8)
        WinUsb_ReadPipe(handle, 0x82, buf, size, ...);            // eMMC/VGA: EP2 IN
    else if (size >= 0x41) {
        // Параллельное чтение: EP2 IN + EP3 IN, по половине размера
        WinUsb_ReadPipe(handle, 0x82, buf, size/2, ...);
        WinUsb_ReadPipe(handle, 0x83, buf+size/2, size/2, ...);
    }
}
```

Подтверждено: **eMMC bulk-read = EP2 IN (pipe 0x82)**. Для не-eMMC больших
чтений Xgpro полосует на **EP2 IN + EP3 IN**.

### 19.12 `FUN_004dbd00` — это `WinUsb_SetPipePolicy`, не "set timeout"

```c
WinUsb_SetPipePolicy(handle, 0x81, PIPE_TRANSFER_TIMEOUT, 4, &timeout_ms);
WinUsb_SetPipePolicy(handle, 0x82, PIPE_TRANSFER_TIMEOUT, 4, &timeout_ms);
WinUsb_SetPipePolicy(handle, 0x83, PIPE_TRANSFER_TIMEOUT, 4, &timeout_ms);
```

Подтверждает, что **EP3 IN (pipe 0x83) реально существует** в дескрипторе.

### 19.13 `BEGIN_TRANSACTION` (top-opcode `0x03`) для eMMC **НЕ нужен**

В главном диспетчере eMMC `FUN_004c9110` (~1700 строк декомпиляции) —
**4 вызова `FUN_004af370` (init sub-step) и только 1 raw send**, нигде
нет top-opcode `0x03`. То есть:

- **Нашему ПО НЕ нужно слать 64-байтный `BEGIN_TRANSACTION` для eMMC.**
- Роль `BEGIN_TRANSACTION` (выбор алгоритма + voltages) для eMMC играет
  **opcode `0x21`** с 1-байт параметром из `DAT_007485d0` (Xgpro
  устанавливает его раньше по выбору `variant` пользователем).
- Практический вывод: start-up в прототипе упрощается до
  `connect()` → opcode `0x21` (+param) → `0x05` → `0x06` → CMD6 SWITCH HS-200.

### 19.14 Полная карта endpoint'ов (после Ghidra)

| Pipe ID | Направление | Роль                                                |
|---------|-------------|-----------------------------------------------------|
| `0x01`  | EP1 OUT     | Все команды; combined 528-byte для не-eMMC          |
| `0x02`  | EP2 OUT     | Bulk-write payload для eMMC                         |
| `0x03`  | EP3 OUT     | Параллельная половина больших не-eMMC записей       |
| `0x05`  | EP5 OUT     | Только VGA bulk-write                               |
| `0x81`  | EP1 IN      | Все короткие ответы (8/24/32 байт)                  |
| `0x82`  | EP2 IN      | Format B reply для eMMC; bulk-read eMMC + VGA       |
| `0x83`  | EP3 IN      | Параллельная половина больших не-eMMC чтений        |

Для нашего eMMC ISP пути нужны только **EP1 OUT/IN и EP2 OUT/IN**.

### 19.15 Новый top-opcode `0x26` — FPGA bitstream download

`FUN_004bb4d0` (`download_algo`) реализует загрузку FPGA-битстрима с PC
для **VGA** (chip_type 8) и, возможно, других «download from PC» случаев.
Три стадии:

| Пакет (LE байты)    | Назначение                              |
|---------------------|-----------------------------------------|
| `26 00 00 20 ......`| Init download (размер в `param_4`)      |
| `26 01 ss ss ......`| Chunk (`0x1F8` байт каждый)             |
| `26 02 ss ss ......`| Wait DONE, error code в `reply[2]`      |

Для eMMC **не используется** (eMMC algorithms хранятся на плате
программатора и выбираются opcode `0x21`).

---

## 20. Напряжения, OVC (защита от перегрузки), pin detect

### 20.1 Поправка: `BEGIN_TRANSACTION` для eMMC **используется**

В §19.13 я ошибся: смотрел только верхнеуровневый dispatcher `FUN_004c9110`,
а 64-байтный `BEGIN_TRANSACTION` пакет отправляется на уровень ниже —
в `FUN_00444bc0` (`pin_detect_pass`), который вызывается перед каждой
eMMC-операцией.

Правильная картина:

```
1. UI «выбор чипа»:
     FUN_004edaa0 копирует поля чипа из БД (Ic_100) в глобалы
     DAT_007a39xx (protocol_id, variant, voltages, sizes, …)

2. Старт операции (Read/Write/Verify…):
     FUN_00444bc0 (pin_detect_pass):
       a. Собрать 64-байт BEGIN_TRANS пакет из глобалов
       b. raw_send(handle, packet, 0x40)              ← EP1 OUT
       c. raw_send(handle, [0x39,0,0,0,0,0,0,0], 8)   ← REQUEST_STATUS
       d. raw_recv(handle, status, 0x20)
       e. if (status[12] & 0x01) {                    ← OVC сработал!
            показать "OverCurrent Protection !"
            raw_send([0x04,0x01,0,…], 8)              ← END_TRANS
            MessageBeep; abort.
          }

3. Дальше — eMMC-инит (opcode 0x21, …)
```

### 20.2 Layout 64-байтного `BEGIN_TRANSACTION` для eMMC

Поля собираются из глобалов `DAT_007a39xx`, которые `FUN_004edaa0`
заполняет из БД-записи `Ic_100` для выбранного чипа. Сокращённая карта
(для eMMC ветки `DAT_007a3978 == 0x31`):

| Pkt offset | Источник              | Поле БД                    | Назначение         |
|-----------:|-----------------------|----------------------------|--------------------|
| `0x00`     | литерал `0x03`        | —                          | top-op BEGIN_TRANS |
| `0x01`     | `DAT_007a3978`        | `protocol_id` (off 0)      | `0x31` для eMMC    |
| `0x02`     | `DAT_007a39a8`        | `variant` low (off 0x34)   | вариант алгоритма  |
| `0x03`     | `DAT_007a3ba6`        | (extra)                    | флаги режима       |
| `0x04..6`  | `DAT_007a39ac` (u16)  | data_memory_size           |                    |
| `0x06`     | `DAT_007a39b4`        | (off 0x44)                 | pin_map/chip_info  |
| `0x10..14` | `DAT_007a397c` (u32)  | code_memory_size (off 0x38)|                    |
| `0x14..18` | mixed                 | voltage encoding           |                    |
| …          | …                     | …                          | другие chip params |

Все поля доступны из дампа `emmc_chips_t48.json` — пакет полностью
собираем оффлайн для любого из 4 796 чипов.

### 20.3 Конфигурация напряжения

Для eMMC напряжение **прошито в BEGIN_TRANSACTION** — отдельной команды
SET_VCC_VOLTAGE не требуется. UI Xgpro предлагает три дискретных VCCQ
(всегда с VCC=3.0V):

```
"VCC=3.0V VCCQ=1.2V"
"VCC=3.0V VCCQ=1.8V"  ← типовой для современных eMMC
"VCC=3.0V VCCQ=3.0V"
```

И fine-trim: `VCCQ + 0.0V / +0.1V / +0.2V / +0.3V`.

Выбор `VCCQ` идёт через **выбор `variant` чипа в БД** перед отправкой
BEGIN_TRANS. Например `variant = 0x4100` → ISP 1-bit, 1.8В;
`variant = 0x4133` → ISP 1-bit, 3.3В (`0x33` = `'3'`).

Для классических чипов используется отдельный opcode `0x1B`
(`SET_VCC_VOLTAGE`) — см. minipro `t48_set_vcc_voltage()`.

### 20.4 Overcurrent protection (OVC)

Точное соответствие с minipro `t48_get_ovc_status`:

| Шаг | Байты (LE)                  | Смысл                                         |
|-----|------------------------------|-----------------------------------------------|
| 1   | `39 00 00 00 00 00 00 00`   | send `REQUEST_STATUS` (8 байт EP1 OUT)        |
| 2   | recv 32 байт EP1 IN          | status block                                  |
| 3   | `reply[12] & 0x01`           | флаг OVC (1 = сработал, 0 = OK)               |

Другие поля 32-байтного status reply:
- `reply[0]` — error code последней операции
- `reply[2..4]` — counter `c1` (LE u16)
- `reply[4..6]` — counter `c2` (LE u16)
- `reply[8..12]` — verify-write address (LE u32)
- `reply[12]` — **OVC байт**

При срабатывании OVC Xgpro шлёт END_TRANS с byte 1 = 0x01:
```
04 01 00 00 00 00 00 00
```
и показывает «OverCurrent Protection !» + системный beep.

### 20.5 Pin detect

Pin detect выполняется **в том же `FUN_00444bc0`** — отдельной команды
(как minipro `READ_PINS = 0x35`) нет. Информация о направлении пинов /
pull-ups уже закодирована в самом BEGIN_TRANS пакете (из
`pin_map`/`package_details`). Результат приходит в тех же 32 байтах
status reply вместе с OVC.

Строки UI:
- `"Pin Detected Passed."` — всё ОК
- `"Pin Detected ERROR!"` / `"Bad PINs Connection."` — pin не подключён
- `"Pin Detect error!/ Direction"` — направление пина неверное

Конкретные биты в reply для pin-flags — TBD (нужен USB-дамп для
точного маппинга). Но OVC и pin live в одной 32-байтовой структуре.

### 20.6 Таймауты пайпов

`FUN_004dbd00` (см. §19.12) ставит `PIPE_TRANSFER_TIMEOUT` на
`0x81/0x82/0x83` перед длинными операциями. Xgpro использует:
- 5 000 мс для EXT_CSD read
- 50 000 мс для обычных read'ов

Всегда устанавливай таймаут перед длинной сессией.

---

## 21. Напряжения: полная картина (поправка)

Раньше я писал «VCC = 3.0 V (фиксировано)» для eMMC. Это лишь как UI Xgpro
маркирует три дискретных VCCQ-пресета — реальное железо T48 поддерживает
гораздо более широкий диапазон.

### 21.1 Реальные диапазоны DAC (из minipro)

| Рейл   | Шагов | Диапазон (V)              | Шаг (тип.) | API в minipro                            |
|--------|------:|---------------------------|------------|------------------------------------------|
| VCC    |    64 | **1.74 .. 6.86**          | ~0.08 V    | `t48_set_vcc_voltage(index 0..63)`        |
| VPP    |    64 | **9.31 .. 25.16**         | ~0.25 V    | `t48_set_vpp_voltage(index 0..63)`        |
| VCCIO  |     5 | 2.35, 2.47, 2.93, 3.23, 3.45 | —       | `t48_set_vccio_voltage(index 0..4)`      |
| VUSB   |     — | (только measure)          | —          | `MEASURE_VOLTAGES`                        |

Точные таблицы (`VCC_MAP`, `VPP_MAP`, `VCCIO_MAP`) — в `examples/t48_emmc.py`.

### 21.2 Как реально устанавливается напряжение

```
SET_VCC voltage:
   msg[0]=0x2E (T48_SET_VCC_PIN), msg[0x10]=J13/J14 enable bits,
   msg[0x14]=0 (DAC hold), msg[0x16]=vcc_index (1..63)
   → 48 байт EP1 OUT.

SET_VPP voltage (programming voltage):
   msg[0]=0x2F (T48_SET_VPP_PIN), msg[1]=0x01 (sub-cmd "set VPP"),
   msg[8]=vpp_index (0..63)
   → 48 байт EP1 OUT.

SET_VCCIO voltage:
   msg[0]=0x2F, msg[1]=0x02, msg[8]=vccio_index (0..4)
   → 48 байт EP1 OUT.
```

### 21.3 Чтение реальных напряжений

```
MEASURE_VOLTAGES (opcode 0x33):
   msg[0]=0x33, padded to 16 bytes → send EP1 OUT (16)
   recv 24 байта EP1 IN, потом:
       vpp   = u16(reply[8])  * 0x0F78  / 0x1000  / 100
       vusb  = u16(reply[12]) * 0xCCF6  / 0x27000 / 100
       vcc   = (u16(reply[16]) * 0xB32E / 0x27000 - 0x14) / 100
       vccio = u16(reply[20]) * 0x0294  / 0x1000  / 100
```

Это позволяет проверить, что DAC **реально** выдаёт ожидаемые вольты —
до подключения чипа.

### 21.4 Возможности железа vs ограничения софта

Есть два слоя «что разрешено»:

**A. Железо T48 (DAC'и):**

| Рейл   | Шагов | Диапазон                  | Разрешение  |
|--------|------:|---------------------------|-------------|
| VCC    |    64 | 1.74 .. 6.86 V            | ~80 мВ      |
| VPP    |    64 | 9.31 .. 25.16 V           | ~250 мВ     |
| VCCIO  |     5 | {2.35, 2.47, 2.93, 3.23, 3.45} V | — |

DAC'и **не произвольные** — это 64-step lookup'ы — но для VCC и VPP
разрешение достаточно мелкое чтобы попасть в любую разумную datasheet-цель.

**B. Xgpro UI / прошивка (реально предлагаемые пресеты):**

Для **классических** чипов UI предлагает ~16 дискретных значений:
`1.20 / 1.80 / 2.50 / 3.00 / 3.30 / 4.00 / 4.50 / 4.75 / 5.00 / 5.25 /
5.50 / 6.00 / 6.25 / 6.50 V`, каждое + fine-trim `±0.3 В` шагом `0.1 В`.
На практике для классики попадаешь в любой нужный voltage с
гранулярностью `100 мВ`.

Для **eMMC** UI намного строже — только три JEDEC IO-класса + такой же
fine-trim:

```
VCC  = 3.0 V (жёстко)
VCCQ ∈ {1.2 V, 1.8 V, 3.0 V}     ← через `variant` чипа в БД
fine-trim: VCC и VCCQ ±0.3 В шагом 0.1 В
```

Это **не** потому, что HW не может — может. Это потому, что JEDEC
определяет VCCQ как дискретные классы, и реальный eMMC-контроллер
специфицирован только в пределах одного из этих окон. Поставить
`VCCQ = 2.5 V` поместит IO-deck чипа в undefined zone — в лучшем
случае команды игнорируются, в худшем — latch-up.

**Можно ли выставлять VCC/VCCQ произвольно в своём ПО?**

Для классического пути: **да** — `set_vcc_voltage(0..63)` и
`set_vpp_voltage(0..63)` уже дают прямой 64-шаговый контроль.

Для eMMC пути: **не надо**. Напряжения зашиты в 64-байтном
`BEGIN_TRANSACTION` через `variant`. Выбор не того variant (например
`_33` суффикс на 1.8 В чипе) убивает чип за миллисекунды — см. §22.6.
Правильный knob для пользователя — это **выбор чипа** (с VCCQ из его
datasheet), а не свободный voltage spinbox.

Если реально нужна off-class VCCQ — например, характеризовать чип на
2.0 В — делай это на жертвенной детали через прямой
`set_vcc_voltage()`, никогда на устройстве, которое жалко.

### 21.5 Где здесь eMMC

Для eMMC сессий Xgpro **не** дёргает отдельные `SET_VCC_VOLTAGE` /
`SET_VPP_VOLTAGE`. Напряжения попадают в 64-байтный BEGIN_TRANSACTION
через поле `variant` чипа. UI-метки `VCC=3.0V VCCQ={1.2,1.8,3.0}V` —
три стандартных класса IO-напряжения eMMC (HS-200 / HS-400 / legacy).

Для нашего кода: для eMMC используй `begin_transaction(...)`, а не
дискретные setter'ы. Дискретные — для классических чипов.

---

## 22. **Безопасная процедура работы** — *не пропускай*

> ⚠️ Этот раздел — самый важный, если собираешься тестировать с живым
> eMMC. **Неверное VCCQ (например 3.3 В на 1.8 В eMMC) убивает чип за
> миллисекунды — и возможно host SoC, который сидит на том же rail.**

### 22.1 Разовая настройка стенда

1. **Первое включение T48:** воткни в USB **без чипа и без адаптера**.
   Запусти Xgpro → `Tools → System Self-check`. Селф-тест
   (`SELFTEST_SET_VCC/VPP/GND`, `SELFTEST_READ_IO`) проверяет каждый
   рейл и каждый pin-драйвер. **Не пропускай на новом T48.**
2. **Жертвенный eMMC** для ранних USB-экспериментов: используй
   *дохлый телефонный eMMC* на breakout-плате, не работающее
   устройство. Тестировать CMD25 на $2000 плате — лучший способ
   узнать, что boot-партиция перезаписана не туда.

### 22.2 Pre-flight каждой сессии

**Перед** любой командой, которая может подать питание на цель:

1. **Идентифицировать чип по datasheet.** Производитель + part number.
   У "1.8V" eMMC tolerance 1.7-1.95V; у "3.3V" — 2.7-3.6V. 1.8V eMMC
   3.3В НЕ простит.
2. **Выбрать правильный variant в БД** (`emmc_chips_t48.json`):
     - `_(ISP)_1Bit` + `_18` → variant `0x4100`, VCCQ = 1.8 В
     - `_(ISP)_1Bit` + `_33` → variant `0x4133`, VCCQ = 3.3 В
     - `_(ISP)_4Bit` + `_18` → variant `0x4400`, VCCQ = 1.8 В
     - `_(ISP)_4Bit` + `_33` → variant `0x4433`, VCCQ = 3.3 В
3. **Подключить ISP по схеме руководства.** Минимум 6 проводов:
   `GND × 2`, `CLK`, `CMD`, `DAT0`, `VCCQ`. Два GND, не один. Резистор
   на CLK на плате — **выпаять**.
4. **`RST_n` eMMC должен быть в `1`.** Проверь мультиметром: `RST_n`
   ~ `VCCQ` при поданном питании в idle. Если 0 → подтянуть ~1 кОм к
   `VCCQ`. Иначе eMMC не стартует или, хуже, latch-up.
5. **Остановить host SoC.** Если eMMC на плате телефона/роутера/ТВ,
   host CPU будет драться с T48 за шину сразу при подаче питания.
   Рецепт из руководства: **закоротить кварц host MCU на землю**,
   чтобы остановить его clock. Проверь, что host в reset.
6. **Только оригинальный адаптер.** XGecu EMMC-ISP VER 1.00 содержит
   secure-element, прошивка его проверяет. Подделки дают
   `Adapter not matched` *до* подачи питания на чип — это тоже
   защитная фича.

### 22.3 Безопасная последовательность старта

Порядок важен. С холодного:

1. **ПК ← USB ← T48** (программатор подключён, но программа ещё
   ничего не отправляет).
2. **Адаптер в ZIF**, рычаг вниз.
3. **Probe адаптера → ISP-точки на плате-цели** (T48 пока не подаёт
   питание на пробник).
4. **Подача питания на плату-цель.** `VCCQ` поднимается с её стороны
   (обычно от родного PMIC). Проверь мультиметром на пробнике:
   `VCCQ` ≈ то, что задекларировал variant.
5. **Запуск программы.** Первая команда — 64-байтный
   `BEGIN_TRANSACTION`:
   - T48 конфигурирует свои IO-драйверы под variant, затем
     `REQUEST_STATUS` (`0x39`) → recv 32 байт → проверка
     `reply[12] & 0x01`.
   - Если OVC сработал, firmware уже отключил драйверы. Программа
     должна отправить `END_TRANSACTION` с `byte 1 = 0x01` и
     **прервать сессию**. **Не повторять без диагностики.**
     `External short or IC reverse or incorrect package!` — три
     основные причины.
6. **Только после чистого `BEGIN_TRANSACTION`** идут opcode `0x21`
   (eMMC init), `0x05` (CID), `0x06` (CSD), CMD6 SWITCH к HS-200, и
   уже потом любые user-level операции.

### 22.4 Во время сессии

- **Каждый ответ — opt-in valid.** `reply[1]` (Format A/B) = 0 →
  OK, иначе код ошибки. Не делать вид что всё хорошо.
- **Ограничивать время операции** per-pipe timeout'ом (§19.12 /
  §20.6). Для ECSD ~5 c, для полного USER — минуты.
- **Периодическая OVC проверка.** Чистый `BEGIN_TRANSACTION` не
  гарантирует, что rails останутся чистыми. После каждого
  CMD25-burst, после каждого partition switch, перед каждым длинным
  bulk-read → `REQUEST_STATUS` + проверка `reply[12] & 0x01`. Если
  стал 1 — немедленно прервать.

### 22.5 Завершение сессии — *всегда*

```
1. STOP_AND_STATUS (Format A, sub-op 0x4C, arg=0)   // CMD12 stop
2. SWITCH к USER (op 0x46, arg 0x02B30700)          // вернуть default partition
3. END_TRANSACTION (top-op 0x04, byte1=0)           // отпустить программатор
4. Снять probe с цели *до* выключения питания цели
5. Выключить питание цели, потом закрыть программу / вынуть USB
```

Если что-то в 1-3 не удалось — всё равно делать 4-5 по порядку.
Выключать цель пока программатор ещё драйвит сигналы — типичный
способ получить latch-up.

### 22.6 Типичные способы убить чип — и как их избежать

| Ошибка                                              | Результат           | Что делать                                          |
|-----------------------------------------------------|---------------------|-----------------------------------------------------|
| `_33` variant на 1.8 В чип                          | Чип умер за мс      | VCCQ из datasheet *до* кода                          |
| Подать питание на цель ДО probe                     | Bus contention      | Probe первый, питание цели — второй                 |
| Пропустить pull-up на `RST_n`                       | Init fail / latch-up| 1 кОм к VCCQ, проверь мультиметром                  |
| Не остановить host SoC                              | CRC errors / latch-up | Закоротить кварц host MCU                         |
| Считать OVC transient и повторить                   | Hard short → урон  | Прервать, исправить wiring, потом retry             |
| Запись RPMB без правильного Auth-Key                | RPMB заперт навсегда | Не включай RPMB write без ключа на руках            |
| Отключение USB посреди операции                     | eMMC в undefined    | END_TRANS первый, потом отключать                   |
| Подделка адаптера, обходящая auth                   | Все ставки сняты    | Только оригинальный XGecu EMMC-ISP VER 1.00         |

### 22.7 Safety-обёртка в коде

В прототипе `begin_session_with_ovc_check()` уже делает pre-flight OVC
check. Для длинных сессий оборачивай операции так:

```python
emmc = T48Emmc(); emmc.connect()
try:
    result = emmc.begin_session_with_ovc_check(packet64)
    if not result['success']:
        raise RuntimeError("OVC trip: " + ovc_diagnosis(result['status']))

    info = emmc.init_emmc(algo_param)
    if info['ocr'] is None or info['cid'] is None:
        raise RuntimeError("eMMC не ответил чисто на init")

    for chunk_idx in range(...):
        if emmc.check_ovc():
            raise RuntimeError("OVC tripped в середине сессии")
        data = emmc.bulk_read(N_SECTORS_PER_CHUNK)
        # ...
finally:
    try: emmc.stop_and_status()
    except Exception: pass
    try: emmc.restore_user_access()
    except Exception: pass
    try: emmc.end_transaction(0)
    except Exception: pass
    emmc.close()
```

`try / except` вокруг каждого shutdown-шага гарантирует освобождение
программатора, даже если один из cleanup-шагов упал — критично, чтобы
не оставлять eMMC bus под напряжением при выходе процесса.

### 22.8 Pre-flight self-check (Ghidra-decoded)

> **Проверено на железе в §31.** Последовательность опкодов ниже верна,
> но живой захват показал: ответы `READ_PINS` — **16 байт (6-байтная
> битмаска пинов с offset 8), а не 40** — см. §31.2.

Xgpro System Self-check (`FUN_004532e0`) — это **самый безопасный паттерн
активации**, который сам firmware использует для самопроверки. Можно
воспроизвести в своём ПО для проверки железа без чипа в socket'е.

```
PRE: чип и адаптер не вставлены в ZIF.

1. send 8B  [0x2D, …]                ; RESET_PIN_DRIVERS
2. download "TestVcc.alg" битстрим   ; через top-op 0x26
3. send 8B  0x2D                     ; reset после битстрима

4. VCC test loop:
   a. send 32B [0x2E, …]             ; SET_VCC_PIN
   b. send 8B  [0x35, …]             ; READ_PINS
   c. recv 40B (0x28)                ; reply[8..48] = pin status
   d. fail → "SELFTEST_SET_VCC cmd error!"

5. VPP test (то же с 0x2F):           ; SET_VPP_PIN + READ_PINS + 40B reply

6. download "TestGnd.alg"
7. 8B 0x2D
8. GND test (32B 0x30 + 8B 0x35 + 40B reply)
9. SET_OUT test (32B 0x36 + READ_PINS)
10. Combined test (0x2D + 0x2E + 0x30 + 0x39 REQUEST_STATUS)
```

Test-битстримы `TestVcc.alg`/`TestGnd.alg` замыкают каждый pin driver
на известную internal reference в FPGA — поэтому **чип не запитывается**,
и это единственная USB-активность, **полностью безопасная без чипа**.

---

## 23. Ещё два top-opcode

### 23.1 `0x0A` — generic eMMC CMD wrapper

`FUN_00495060` (программирование CSD с OTP-битом) использует
**32-байтный raw-пакет** оборачивающий любую JEDEC eMMC CMDxx с
16-байтным payload'ом:

```c
struct EP1_RawCmd_0x0A {        // всего 32 байта
    uint32_t header;            // = 0x000A0001  (top-op=0x0A)
    uint32_t pad0;              // = 0
    uint32_t size;              // = 0x00100000
    uint32_t jedec_cmd;         // JEDEC eMMC CMD номер (например 0x5B = CMD27)
    uint8_t  data[16];          // CMD аргумент / payload
};
// → send 0x20 байт EP1 OUT
// → recv 8 байт EP1 IN (reply[1] = status)
```

Использование: CMD27 PROGRAM_CSD (`jedec_cmd = 0x5B`). Этот wrapper
универсален для любой CMDxx с 16-байт data. Xgpro перед raw-send делает
два Format-A вызова (sub-op `0x57` arg=1, потом sub-op `0x50` arg=0x10),
после raw-send — финальный sub-op `0x50` arg=0x200 (commit).

### 23.2 `0x35` — `READ_PINS` (карта пинов)

Используется self-check для чтения состояния всех 40 пинов ZIF:

```
send 8B [0x35, 0,…]                    ; EP1 OUT
recv 40B (0x28)                         ; EP1 IN
// reply[8..48] = pin status (1 байт на pin)
```

minipro реализует для TL866II+, но **не для T48** (`pin_test = NULL` в
T48-структуре). Опкод, размеры и layout reply совпадают — добавить
T48 pin-test в minipro = ~30 строк патча.

### 23.3 Обновлённая таблица top-opcodes (финальная)

| Top-op | Источник           | Назначение                                          |
|--------|--------------------|-----------------------------------------------------|
| `0x02` | minipro classic    | `NAND_INIT`                                         |
| `0x03` | both               | `BEGIN_TRANSACTION` (64 байт, и для eMMC тоже)      |
| `0x04` | both               | `END_TRANSACTION` (8 байт; byte 1 = OVC-abort)      |
| `0x05` | both               | `READID` (CID для eMMC init)                        |
| `0x06` | both               | `READ_USER` (CSD для eMMC init)                     |
| `0x08` | Xgpro NEW          | Long-recv envelope (sub `0x48` = 512B read)         |
| **`0x0A`** | **Xgpro NEW**  | **Generic eMMC CMDxx wrapper (32 байта)**           |
| `0x14` | Xgpro NEW          | Bulk-write setup перед EP2 OUT                      |
| `0x1B` | minipro classic    | `SET_VCC_VOLTAGE`                                   |
| `0x1C` | minipro classic    | `SET_VPP_VOLTAGE`                                   |
| `0x21` | Xgpro NEW          | eMMC init / выбор алгоритма                         |
| `0x26` | Xgpro NEW          | FPGA bitstream download (`TestVcc.alg`, `TestGnd.alg`) |
| `0x27` | Xgpro NEW          | eMMC sub-command dispatcher                         |
| `0x2D` | minipro classic    | `RESET_PIN_DRIVERS` (self-check между фазами)       |
| `0x2E` | minipro classic    | `SET_VCC_PIN` (32 байта)                            |
| `0x2F` | minipro classic    | `SET_VPP_PIN` (sub 1 = VPP, sub 2 = VCCIO)          |
| `0x30` | minipro classic    | `SET_GND_PIN` (32 или 40 байт)                      |
| `0x33` | minipro classic    | `MEASURE_VOLTAGES`                                  |
| **`0x35`** | both           | **`READ_PINS`** (40 байт reply — карта пинов)       |
| `0x36` | minipro classic    | `SET_OUT`                                           |
| `0x39` | both               | `REQUEST_STATUS` (32 байта; OVC@12)                 |
| `0x3F` | minipro classic    | `RESET`                                             |

## 24. RPMB протокол — карта request-кодов

`FUN_004afd10` показывает соответствие `req` arg в `FUN_00492670`
с **JEDEC RPMB request кодами**:

| `req` arg | JEDEC RPMB request | Назначение                                |
|-----------|--------------------|-------------------------------------------|
| `1`       | `0x0001 PROGRAM_KEY` | Запись 32-байт Authentication Key (one-shot) |
| `2`       | `0x0002 READ_WC`     | Read write counter                        |
| `3`       | `0x0003 AUTH_DATA_WRITE` | Authenticated write (1 сектор за раз) |
| `4`       | `0x0004 AUTH_DATA_READ`  | Authenticated read                    |
| `5`       | `0x0005 READ_RESULT`     | Чтение response register              |

Два хардкод-table с ключами в static data:

| Символ           | Размер | Назначение                                       |
|------------------|--------|--------------------------------------------------|
| `DAT_0079A690`   | 32 B   | Default/factory RPMB ключ #1                      |
| `DAT_007C8048`   | 32 B   | Default/factory RPMB ключ #2                      |

`FUN_00492670` arg `param_10` выбирает (`1` = первая table, `2` = вторая).

> ⚠️ **`PROGRAM_KEY` — one-shot на чип**. Записать ключ можно только
> один раз. Если запустить против чипа без своего ключа — RPMB-write на
> нём отключится навсегда. Наш `build_rpmb_frame()` берёт `key_mac` явным
> параметром именно чтобы этого не случилось случайно.

## 25. CARD STATUS — semantics и error-коды

### 25.1 Поправка: sub-op `0x4D` это **НЕ** «commit»

Раньше (§19.4, §20.2) я писал что sub-op `0x4D` — это «commit / finalize FPGA».
**Это была ошибка.** 5-й проход Ghidra нашёл `FUN_004929f0` — функцию
чтения card status — и она отправляет:

```c
uint8_t pkt[8] = {
    0x27,    // byte 0 — top-opcode (Format A)
    0x4D,    // byte 1 — sub-opcode  ← CMD13 SEND_STATUS!
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
};
```

Так что **sub-op `0x4D` = CMD13 SEND_STATUS** (читает 32-бит CARD STATUS
register eMMC). Раньше меня сбила толку контекст «Set Password» —
там просто опрос статуса после записи.

**Обновлённая таблица sub-op'ов Format A:**

| Sub-op | Семантика (исправлено)                                  |
|--------|---------------------------------------------------------|
| `0x46` | CMD6 SWITCH                                             |
| `0x4C` | CMD12 STOP_TRANSMISSION                                 |
| **`0x4D`** | **CMD13 SEND_STATUS** (исправлено)                  |
| `0x50` | Data transfer 512 байт (CMD24 / OTP / RPMB write data)  |
| `0x57` | CMD23 SET_BLOCK_COUNT                                   |
| `0x5C` | TBD (1 call site)                                       |
| `0x5D` | Read WP table                                           |

### 25.2 Decoder error-кодов (`FUN_004b32f0`)

`FUN_004b32f0` — центральный status decoder. Каждое error-сообщение Xgpro
проходит через него. Расшифровка `switch(param_1 & 0xFF)`:

| `reply[0]` | Значение                                                       |
|-----------:|----------------------------------------------------------------|
| `0`        | OK                                                             |
| `1`        | Generic status reply                                           |
| `2`        | CRC error (command CRC)                                        |
| `3`        | CMD1 respond error (init OCR mismatch)                         |
| `4`        | CMD1 no response                                               |
| `5`        | CMDx no response                                               |
| `6`        | eMMC busy                                                      |
| `7`        | "No Data respond" (если bit 25 `param_2` = 0)                  |
| `8`        | DataBus CRC error → подсказка *"Reduce CLK или switch VCCQ"*    |
| `9`        | Write CRC error                                                |
| `10`       | eMMC `DAT0` busy (если bit 25 `param_2` = 0)                   |
| `0xE1`     | "EMMC stops responding 1" (firmware timeout)                   |
| `0xE2`     | "EMMC stops responding 2"                                      |
| `0xE3`     | "EMMC stops responding 3"                                      |
| `0xEE`     | "EMMC stops responding 0"                                      |

`param_2` — это **JEDEC eMMC CARD STATUS register** (R1 response, 32 бита):

| Биты   | Поле               | Значение                              |
|-------:|--------------------|---------------------------------------|
| 25     | `READY_FOR_DATA`   | 1 = чип готов принять данные          |
| 12..9  | `CURRENT_STATE`    | Состояние машины:                     |
|        |                    | 0=IDLE, 1=READY, 2=IDENT, 3=STBY, **4=TRAN**, 5=DATA, 6=RCV, 7=PRG, 8=DIS, 9=BTST, 10=SLP |

### 25.3 Erase wait loop (`FUN_004acee0`)

```c
int max_iter = 10000;
int rc = read_card_status(handle, &status_buf);   // Format A op 0x4D
while (rc != -1) {
    uint32_t card_status = *(uint32_t*)&status_buf[4];
    if ((card_status & 0x1E00) == 0x800) break;    // CURRENT_STATE == TRAN
    rc = format_A_cmd(handle, /*sub_op=*/0x4C, 0, &status_buf);  // CMD12 STOP
    if (rc == -1) { report(" -- CMD12"); break; }
    if (--max_iter == 0) { report(" -- Erase Timeout"); break; }
    rc = read_card_status(handle, &status_buf);
}
```

Главное:
- **CMD13** через sub-op `0x4D` (НЕ через top-op `0x39` — тот REQUEST_STATUS
  программатора, с OVC@12).
- 32-бит CARD STATUS читается из `reply[4..8]`.
- Polling до `CURRENT_STATE == 4 (TRAN)`, CMD12 между опросами.
- 10000 итераций ≈ полное стирание чипа; иначе "Erase Timeout".

---

## 26. Финальный реверс-проход — erase, variant-буквы, sub-op 0x5E

### 26.1 Xgpro **не использует** JEDEC CMD35/36/38 для eMMC erase

`FUN_0049e010` (Erase Partition, 1353 строки декомпиляции) **не содержит**
CMD35 → CMD36 → CMD38 sequence. Функция только читает ECSD erase-поля
для display: `ERASE_GROUP_DEF[175]`, `ERASE_GRP_SIZE`, `ERASE_GRP_MULT`,
`SEC_ERASE_MULT`, `ERASE_TIMEOUT_MULT`. Реальный "erase" = просто
**CMD25 WRITE_MULTIPLE_BLOCK с zero (или 0xFF) pattern**.

Для нашего ПО: write-before-erase **не нужен как отдельный шаг**.
UI-опция "Erase before programming" в Xgpro = zero-fill через CMD25.

### 26.2 Sub-op `0x5E` под top-op `0x08` — CMD30 wrapper

`FUN_00492aa0` (helper из erase path) строит Format B команду с
sub-op `0x5E` и length=4. При ошибке выводит "Write device Error CMD30
request!". JEDEC CMD30 `SEND_WRITE_PROT` возвращает 32-бит карту
write-protect для группы.

| Format | Top-op | Sub-op | Length | Назначение            |
|--------|--------|--------|--------|-----------------------|
| B      | `0x08` | `0x5E` | 4 B    | CMD30 SEND_WRITE_PROT |

### 26.3 Variant letter encoding — ASCII high byte `variant`

`FUN_004e18d0` (pin-fault mask selector для eMMC) использует
`DAT_007a39a9` — **high byte variant**, интерпретируемый как ASCII:

| Буква  | Hex   | Bus mode  | Adapter type | `.alg` семейство |
|:------:|:-----:|-----------|--------------|------------------|
| `A`    | 0x41  | 1-bit     | ISP          | `EMMC_41_…`      |
| `D`    | 0x44  | 4-bit     | ISP          | `EMMC_44_…`      |
| `Q`    | 0x51  | 1-bit     | BGA socket   | `EMMC_51_…`      |
| `S`    | 0x53  | 8-bit     | BGA socket   | `EMMC_53_…`      |
| `T`    | 0x54  | 4-bit     | BGA socket   | `EMMC_54_…`      |

Эти буквы управляют:
- именованием `.alg` файлов (`EMMC_<hex>_{18,33}.alg`)
- **expected-pin bitmask** возвращаемым `FUN_004e18d0` (диагностика
  знает какие пины должны быть live для конкретной variant)

Bitmask значения (`0x0AB8A3FE`, `0x0AB8A1E0`, …) кодируют какие T48 pin
lines routed к какому eMMC ball для этой variant. Полезно при
диагностике «Bad Pin On ISP».

---

## 27. Ветка работы с eMMC-ISP адаптером

### 27.1 Выбор variant — что считается ISP

Чип с variant high byte `'A'` (`0x41`) или `'D'` (`0x44`) — т.е.
варианты `0x41xx` / `0x44xx` — идёт в **ISP-ветку**. Low byte = voltage:

| variant   | режим            | алгоритм             |
|-----------|------------------|----------------------|
| `0x4100`  | ISP 1-bit, 1.8 V | `EMMC_41_18.alg`     |
| `0x4133`  | ISP 1-bit, 3.3 V | `EMMC_41_33.alg`     |
| `0x4400`  | ISP 4-bit, 1.8 V | `EMMC_44_18.alg`     |
| `0x4433`  | ISP 4-bit, 3.3 V | `EMMC_44_33.alg`     |

`FUN_004e18d0` (§26.3) для high byte возвращает **expected pin bitmask**:
`'A' → 0x0AB8A018`, `'D' → 0x0AB8A0DC`. Это с чем сравнивается actual
status reply для определения **какой именно пин** отвалился.

### 27.2 Top-opcode `0x2B` — adapter command channel (новый!)

`FUN_004583f0` (около "Adapter not matched, use:") говорит с адаптером
через **новый top-opcode**, не виденный раньше:

```c
void adapter_cmd(handle, byte param_a, byte param_b) {
    uint8_t pkt[8];
    *(u16*)&pkt[0] = 0xFF2B;             // byte 0 = 0x2B, byte 1 = 0xFF
    raw_send(handle, pkt, 8);            // 1й пакет: query adapter

    *(u16*)&pkt[0] = 0x022B;             // byte 0 = 0x2B, byte 1 = 0x02
    *(u16*)&pkt[2] = param_b;
    *(u32*)&pkt[4] = param_a;
    raw_send(handle, pkt, 8);            // 2й пакет: configure adapter
}
```

Так что **top-op `0x2B` — adapter channel**:

| `pkt[1]` | Назначение (предв.)                          |
|---------:|----------------------------------------------|
| `0xFF`   | "query adapter" / start transaction          |
| `0x02`   | "set adapter params" (с 2- + 4-байт payload) |

Это **отдельно от** secure-element аутентификации между **адаптером ↔
прошивкой T48**. С ПК мы видим только **конфигурацию** адаптера через
firmware.

Для нашего ПО:
- Реверс crypto не нужен.
- Возможно нужно слать те же `0x2B/0xFF` + `0x2B/0x02` перед первой
  eMMC-операцией, чтобы прошивка знала какой адаптер используется.
- Точные `param_a`/`param_b` — снимать с USB-дампа.

### 27.3 Device identification — пустой пакет → 64 байта info

`FUN_004dba90` — **первое что Xgpro шлёт** на свежий handle:

```c
uint8_t empty_pkt[8] = {0};
WinUsb_WritePipe(handle, 1, empty_pkt, 8, ...);      // EP1 OUT — все нули
uint8_t info[64];
raw_recv(handle, info, 0x40);                         // EP1 IN — 64 байта
if (info[10] ∈ {0x05, 0x06, 0x07}) {
    // valid T48 модель
}
```

Это **критично для нашего прототипа**: как самую первую транзакцию
после `connect()` шлём 8 нулевых байт, читаем 64. `reply[10]` = код
модели (`0x05`/`0x06`/`0x07`); другие поля — firmware version, S/N.

Паттерн "send all-zero команду для banner reply" — стандарт для
vendor-specific WinUSB, теперь подтверждён для T48.

### 27.4 Полный flow ISP-чтения

`FUN_004a98f0` — entry для **ISP-чтения**. Суть:

```c
void isp_read(handle, ..., chip_params, ...) {
    open_temp_file();
    block_count = DAT_007475a4 >> 14;             // total / 16K
    update_ui(...);

    if (!FUN_004fc156(param_7, /*flag=*/0x8040, 0))  // partition switch (ISP-mode bit 0x80)
        bail_out("partition switch failed");

    uint32_t buf[128];
    uint32_t current_addr = 0;
    while (block_count-- > 0) {
        // Format C bulk-write SETUP, req=4 (READ), gen_nonce=1:
        rc = FUN_00492670(handle, buf, current_addr,
                          0, 0, /*count=*/1, /*req=*/4,
                          0, /*gen_nonce=*/1, /*key_src=*/0);
        if (rc == -1) { error("ReadDevice Error : CMD25"); break; }
        // Format D bulk-read 64 секторов (32 КБ) на EP2 IN:
        FUN_00492590(handle, output_buf, /*count=*/0x40);
        save_to_file(...);
        current_addr += 0x40;
    }
}
```

Отличия от BGA-сокет ветки (`FUN_0049d910`):
- ISP **всегда** ставит `gen_nonce=1`. Случайный nonce — часть frame
  даже без ключа. Скорее всего FPGA/прошивка использует nonce как
  wiggle-bit для целостности ISP-сигнала.
- Partition switch обёрнут в `FUN_004fc156(0x8040)`. High byte `0x80` —
  "ISP path bit", low byte `0x40` совпадает с ISP 4-bit variant high.

### 27.5 Adapter integrity check через CRC32 (`FUN_004ee610`)

`FUN_004ee610` считает CRC32 (table в `DAT_006c3300`) над **четырьмя
буферами подряд**:

```c
uint32_t adapter_integrity_crc() {
    uint32_t crc = 0xFFFFFFFF;
    crc = crc32_update(crc, DAT_007a3c0c, DAT_007a397c);   // code-memory buffer
    crc = crc32_update(crc, DAT_007a4034, DAT_007a39ac);   // CID + CSD
    crc = crc32_update(crc, &DAT_007c8048, DAT_007a39b0);  // RPMB key table 2 (32 B!)
    crc = crc32_update(crc, &DAT_007a3c10, 0x100);          // 256-байт config
    return ~crc;
}
```

То что **RPMB-ключ часть хэша** сильно намекает: это **host-side
adapter identity check** — хост должен знать свою копию RPMB-ключа
чтобы получить value, которое адаптер ожидает.

**Для нашего ПО:** ломать этот CRC **не нужно**. Проверка проходит
между ПК-софтом и прошивкой T48 через данные включая чип. Наше ПО
просто шлёт тот же набор `FUN_00492f30 / 00492670 / 00492590` —
прошивка сама ведёт adapter-side challenge.

### 27.6 ISP-read session end-to-end

```
1.  connect() → libusb a466:0a53
2.  identify_programmer()        ; FUN_004dba90 — 8 нулей → 64 байт info
3.  load_chip_params_from_db()   ; FUN_004edaa0 эквивалент локально
4.  adapter_cmd(0x2B, 0xFF, …)   ; top-op 0x2B, sub 0xFF — query
5.  adapter_cmd(0x2B, 0x02, …)   ; top-op 0x2B, sub 0x02 — configure
6.  begin_transaction(packet64)  ; top-op 0x03 — 64-байт BEGIN_TRANS
7.  request_status() → OVC check ; top-op 0x39 — reply[12] & 0x01
8.  init_emmc()                  ; opcodes 0x21 / 0x05 / 0x06
9.  CMD6 SWITCH HS-200 и т.д.    ; Format A sub-op 0x46
10. цикл чтения                  ; Format C setup gen_nonce=1 + Format D bulk read
11. CMD13 polling между bursts   ; Format A sub-op 0x4D
12. CMD12 STOP в конце           ; Format A sub-op 0x4C
13. END_TRANSACTION              ; top-op 0x04
14. close()
```

ISP-специфика — шаги 4-5 (`0x2B` adapter channel) и `gen_nonce=1` на
шаге 10. Всё остальное общее с BGA-socket путём.

### 26.4 Финальные нерешённые опкоды

Без живого железа пока не закроем:
- Sub-op `0x5C` (1 call site, без anchor строк, low priority).
- Точные bit-позиции в 32-байтном REQUEST_STATUS reply для individual
  pin-fault флагов — функции выбирают *expected* mask, но *фактическое*
  per-pin reading нужно сравнить с USB-дампом.
- Полная 64-байтная карта BEGIN_TRANSACTION для не-eMMC веток.

Эти задачи решатся когда приедет железо и снимем USB-дамп.

---

## 28. Поправки — что статический реверс наврал

Это рабочий документ. Финальный проход по «неуверенным» функциям
перед приездом железа исправил три значимые ошибки в §27.

### 28.1 Top-opcode `0x2B` — это **НЕ** eMMC-ISP adapter channel

§27.2 ранее утверждал, что `0x2B` — «adapter command channel» для
ISP-адаптера. Единственный caller `FUN_004583f0` это `FUN_004576a0`,
который в error-путях печатает **«Set Uart Ports error!»** и
**«Starting uart Printer error!»**. Так что:

| Было | Правда |
|---|---|
| `0x2B` = eMMC-ISP adapter command channel | `0x2B` = **UART / Serial-Printer channel** (фича UI "TV Tools → Serial Printing") |
| Слать `0x2B 0xFF` + `0x2B 0x02` перед BEGIN_TRANSACTION | **НЕ слать `0x2B` вообще** для eMMC ISP |
| Нужно для распознавания адаптера | Распознавание адаптера **целиком** между secure-element и прошивкой T48; ПК не участвует |

Это **упрощает** прототип — наш `connect → begin_transaction →
init_emmc → …` правилен как есть, **без шага `0x2B`**.

> **Уточнение (живой захват, §33.1):** USB-видимый канал у адаптера
> всё-таки есть — но это **top-opcode `0x24`**, а не `0x2B`. По `0x24` ПК
> читает строку-идентификатор адаптера (`"XGecu Directly"`); крипто-
> аутентификация по-прежнему идёт мимо провода (между адаптером и
> прошивкой T48), так что тезис «ПК не участвует в auth» выше остаётся в
> силе. Полный eMMC-ISP захват — в §33.

### 28.2 `FUN_004fc156` — это `CreateFileA`, не "partition switch"

§27.4 ранее интерпретировал `FUN_004fc156(param_7, 0x8040, 0)` в ISP
read функции как «partition switch». На самом деле это **textbook
CreateFileA wrapper**:

```c
// param_3 & 0x3   → dwDesiredAccess  (0x80000000 GENERIC_READ и т.д.)
// param_3 & 0x70  → dwShareMode
// param_3 & 0xF00 → dwCreationDisposition
// → CreateFileA / CreateFileW
```

В контексте (`FUN_004a98f0` ISP read) флаг `0x8040` — это **file mode**
для **выходного dump-файла** на хосте, куда сохраняются прочитанные
сектора. Это **открытие файла на ПК**, не команда eMMC. Реальный
partition switch (CMD6 PARTITION_CONFIG) шлётся **раньше**, обычным
`cmd_A(SWITCH, …)` (§19.3 / §20.2).

### 28.3 Sub-op `0x5C` — это 8-counter accumulator (bus test?)

Единственный caller sub-op `0x5C` — `FUN_004b0ca0`, тело которого
накапливает восемь per-byte-position сумм по буферу в цикле:

```c
int counters[8] = {0};
for (int i = 0; i < 4; i++) {
    counters[0] += data[0];   counters[4] += data[4];
    counters[1] += data[1];   counters[5] += data[5];
    counters[2] += data[2];   counters[6] += data[6];
    counters[3] += data[3];   counters[7] += data[7];
    data += 8;
}
// → cmd_A(handle, 0x5C, …) с восемью counter'ами
```

Восемь сумм по битовым позициям — каноничный паттерн **bus integrity
test**: каждый counter отслеживает bit-flips на одной линии 8-бит data
шины. Наиболее вероятно, sub-op `0x5C` = «начать / отчитать bus-test
паттерн» в FPGA. Единственный call site достижим только из
диагностического диалога, в normal read/write пути не вызывается —
**первому прототипу можно не реализовывать**.

### 28.4 Что **реально** TBD (нужен дамп)

После 28.1–28.3 список «неуверенного» — короткий:

- **Точные bit-позиции в 32-байтном REQUEST_STATUS reply** —
  `FUN_004dc6d0` (classic pin decoder) ходит по per-variant таблицам
  `DAT_006B57FC` / `DAT_006B6EE0` и OR'ит флаги в output через
  bit-константы `0x8`, `0x20`, `0x2A`, `0x380`, `0x228000`. Маппинг
  обратно на физические T48 pin номера = **один good-vs-bad-pin USB
  дамп**.
- **Voltage encoding в 64-байтном BEGIN_TRANSACTION** (offset
  `0x14..0x18`) — Xgpro берёт из chip-DB глобалов, но точный
  byte-order vs DAC-индекс таблиц §21.1 закроется одним дампом.
- **`adapter_query` / `adapter_configure`** — удалены из прототипа по
  §28.1; валидировать нечего.

Только эти три вещи реально нужно проверить дампом. Остальное —
byte-for-byte задокументировано из бинаря.

---

## 29. Ещё поправки после перепроверки

Финальный cross-check перед «всё закрыто» нашёл ещё две существенные
ошибки + полезную truth-table для RPMB/CMD18 wrapper.

### 29.1 `DAT_0080109b` — это **модель программатора**, не chip type

Раньше я называл `DAT_0080109b` "chip type" — из-за сравнений типа
`chip_type == 7` в `cmd_wrapper_0x08` и `bulk_read_emmc`. Но функция
которая **устанавливает** этот байт (`FUN_00436e90`) показывает другое:

```c
if (mode == 0)  DAT_0080109b = 6;   // T56 demo
if (mode == 1)  DAT_0080109b = 7;   // T48 demo
if (mode == 2)  DAT_0080109b = 5;   // TL866II Plus demo
// и == 8 для T76.
```

Значит этот байт — **идентификатор семейства программатора**:

| Значение | Программатор      |
|---------:|-------------------|
| `5`      | TL866II Plus      |
| `6`      | T56               |
| `7`      | **T48** (TL866-3G) |
| `8`      | T76               |

Каждая проверка которую я считал «chip-side test» на самом деле —
**programmer-family test**:

| Прежнее чтение | Реальный смысл |
|---|---|
| Format B reply на EP2 IN "для eMMC" | EP2 IN routing на **T48/T76**; на T56 идёт EP1 IN |
| Bulk reads на EP2 IN "для eMMC/VGA" | То же самое — T48/T76 routing |
| `raw_recv` +1 байт "для NAND" | +1 байт **для T56** (model = 6), не связано с типом чипа |

**Практически:** прототип всё равно корректен для T48 ISP — *каждое*
условие "if chip_type 7 or 8" удовлетворяется тем, что мы на T48
(model 7). Но при порте на T56 routing меняется.

Оставляю имя `chip_type` в §19–§22 как есть (git history continuity),
но **мысленно подставлять "programmer model"** при чтении констант
`5 / 6 / 7 / 8`.

### 29.2 Truth-table всех 7 callers `FUN_00492670`

Семь call-сайтов Format C bulk write. С корректной индексацией
push'ей (`pushes[-7]` = `req`, `pushes[-9]` = `gen_nonce`,
`pushes[-10]` = `key_src`):

| Сайт VA   | `count` | `req` | `nonce` | `key` | JEDEC RPMB         | Применение                                  |
|-----------|--------:|------:|--------:|------:|--------------------|---------------------------------------------|
| `0x49388a` | 1      | `5`   | (reg)   | (reg) | `READ_RESULT`      | после password/OTP write — read response    |
| `0x49da64` | 1      | `4`   | `1`     | `0`   | `AUTH_DATA_READ`   | **BGA-mode CMD18 read** (1 сектор)          |
| `0x4a9a64` | 1      | `4`   | `1`     | `0`   | `AUTH_DATA_READ`   | **ISP-mode CMD18 read** — *идентично* BGA   |
| `0x4afd51` | 1      | `4`   | (reg)   | (reg) | `AUTH_DATA_READ`   | RPMB authenticated read                     |
| `0x4afdd5` | 1      | `1`   | (reg)   | `2`   | `PROGRAM_KEY`      | **One-shot key programming, key table #2** |
| `0x4afe07` | 1      | `5`   | (reg)   | (reg) | `READ_RESULT`      | после `PROGRAM_KEY` — read response         |
| `0x4b041b` | 1      | `2`   | `1`     | (reg) | `READ_WC`          | Read write counter                          |

Два важных наблюдения:

1. **`gen_nonce = 1` НЕ ISP-специфика.** BGA CMD18 (0x49da64) ставит
   точно так же как ISP (0x4a9a64). Nonce — часть **каждого** normal
   CMD18 frame, не маркер ISP-mode. Моя §27.4 утверждала обратное —
   это было неверно.

2. **Точно один `PROGRAM_KEY` call site (0x4afdd5)**, и всегда с
   `key_src = 2` (вторая hardcoded table `DAT_007C8048`). Если кто-то
   воспроизводит RPMB flow по нашему коду — обязательно повесить
   `PROGRAM_KEY` за явный opt-in пользователя: это one-shot per chip,
   ошибка = RPMB-write навсегда заблокирован.

### 29.3 ISP-read flow упрощается до BGA-эквивалента

Вместе с §28.2 (`FUN_004fc156` = `CreateFile`, не partition switch),
flow внутри `FUN_004a98f0` теперь:

```c
open_dump_file(host_path);            // FUN_004fc156 — просто файл
while (block_count_left > 0) {
    bulk_write_setup(/*req=*/4, /*gen_nonce=*/1, /*key=*/0);   // CMD18 setup
    bulk_read_data(64 сектора = 32 КБ);
    write_sectors_to_dump_file();
    block_count_left -= …;
}
```

**Никакой отдельной "ISP" обработки** в этой функции (кроме entry
conditions по `variant` high byte — §27.1, остаётся). Сессия
байт-в-байт повторяет BGA read.

Это убирает ещё одно «но» — наш прототип `bulk_read()` не нуждается
в "ISP mode" flag; та же Format C / Format D пара подходит для
**любого** normal eMMC read независимо от как чип подключён.

### 24.1 Two-step «Program Key»

```
1. raw_send Format C req=1 (PROGRAM_KEY)
2. raw_send Format C req=5 (READ_RESULT)
3. raw_recv Format D count=1                          ; 512-байт response
4. parse: byte 0x1FF & 7 = JEDEC OPERATION_RESULT:
   0 = OK
   1 = General failure
   2 = Authentication failure
   3 = Counter failure
   4 = Address failure
   5 = Write failure
   6 = Read failure
   7 = Authentication Key not yet programmed
```

---

## 30. Четвёртый проход поправок — выверенная карта байт `BEGIN_TRANSACTION`

До приезда железа билдер `BEGIN_TRANSACTION` строился по выведенной
таблице §20.2. Свежая **трассировка реальных store-инструкций в
`FUN_00444bc0` через radare2** (а не по списку полей из декомпилятора)
исправила несколько offset'ов. Проход чисто статический и всё ещё
требует сверки с первым реальным захватом, но теперь он на уровне
инструкций, а не догадок.

Воспроизвести:
```
r2 -q -e bin.cache=true -e scr.color=0 -c 's 0x00444bc0; af; pdf' Xgpro.exe
```

### 30.1 Буфер и два пути отправки

- База командного буфера = `[ebp - 0x12018]` = `buf+0x00`.
- Есть **два** пути сборки/отправки, оба шлют `len = 0x40`:
  - **Путь A** (`chip_type == 0x2d`, ветка `0x444c16`): строит *другую*
    раскладку из глобалов `0x0079a8xx`; `push 0x40` на `0x444d22`,
    `call 0x4dc380` на `0x444d26`.
  - **Путь B** (всё остальное — то, что и описывал §20.2): `push 0x40`
    на `0x44501a`, `lea eax,[ebp-0x12018]` на `0x445029`,
    `call 0x4dc380` на **`0x445031`**.
- 8-байтный `REQUEST_STATUS` после этого (путь B) пишет
  `byte[buf]=0x39`, затем `call 0x4dc380` на `0x445079` (len 8), и
  читает 32-байтный ответ в `[ebp-0x24020]` через `call 0x4dc300` на
  `0x445088`. (Хелпер чтения `0x4dc300` ≠ хелпер записи `0x4dc380`.)

### 30.2 Исправленная карта байт пути B (выверено по инструкциям)

| Off | sz | источник по умолчанию | override в ветках |
|----:|----|------------------------|-------------------|
| 0x00 | b | литерал `0x03` | — |
| 0x01 | b | `DAT_007a3978` (chip_type / protocol_id) | — |
| 0x02 | b | `DAT_007a39a8` (variant low) | — |
| 0x03 | b | `DAT_007a3ba6` | — |
| 0x04 | b | `DAT_007a39bc` (cfg-байт `dl`) | перекладывается в 0x15/0x16 в nibble-путях |
| 0x05 | b | `DAT_007a39bd` | перезаписывается в путях 0x31/0x2d/nibble |
| 0x06 | b | `DAT_007a39b4` (pin_map) | — |
| 0x07 | b | `DAT_007a397b` | — |
| 0x08 | w | `DAT_007a39ac` (**data_memory_size — пишется один раз**) | — |
| 0x0a | w | `DAT_007a39c0` (data_memory2_size) | — |
| 0x0c | w | `DAT_007a39c4` (page_size) | путь 0x31 → `DAT_007a39a9` zext |
| 0x0e | w | `DAT_007a39b0` (pulse_delay) | — |
| 0x10 | dw | `DAT_007a397c` (code_memory_size) | — |
| **0x14** | b | **`DAT_007a3979`** (безусловно) | — |
| **0x15** | b | **(по умолчанию нет)** | 0x31: ← `DAT_007485c8`; nibble: `dl & 0x0F` |
| **0x16** | b | **(по умолчанию нет)** | 0x31: ← `0`; nibble: `dl & 0xF0` |
| **0x17** | b | **никогда не пишется (мусор стека)** | — |
| 0x18 | dw | `DAT_00904e88` | перезапись в 0x31/0x2d/0x12/0x34 |
| 0x1c | dw | `DAT_00904e8c` | перезапись в 0x31/0x2d/0x34 |
| 0x20 | dw | `DAT_00904e90` | перезапись в 0x31/0x34 |
| 0x24 | dw | `DAT_00904e94` | `if chip_type==5` → `DAT_0080187b` |
| 0x28 | dw | `DAT_007a39d4` | 0x2d → `DAT_0079a8dc` |
| 0x2c | dw | `DAT_007a39b6` (**u16 zero-extended**) | — |
| 0x30 | dw | `DAT_007a39d0` (i32) | — |
| 0x34 | w | `DAT_007a3ba4` | — |
| 0x36 | w | `DAT_007a39be` (байт → word) | — |
| 0x38 | dw | `DAT_007a39d8` | — |
| 0x3c | b | литерал `0` | 0x34 → `byte[esi+0x696588]` |
| 0x3d | b | литерал `0` | — |
| 0x3e | b | **никогда не пишется (мусор)** | — |
| 0x3f | b | `DAT_007a39a9` | — |

### 30.3 Зона `0x14..0x18` («напряжение») — разобрана

Это **не** u32-слово напряжения. Это три независимых байта плюс один
неинициализированный:

- `0x14` = `DAT_007a3979` — байт из per-chip DB, пишется безусловно.
- `0x15` / `0x16` — пишутся **только внутри лестницы веток `chip_type`**:
  - **eMMC (`chip_type == 0x31`):** `0x15 ← DAT_007485c8`, `0x16 ← 0`.
    `DAT_007485c8` — это **UI/mode-глобал** (выбор VCCQ), а *не*
    per-chip запись. То есть байт VCCQ для eMMC **не выводится из записи
    БД в одиночку** — он отслеживает UI-выбор «VCC=3.0V VCCQ=1.8/3.0V»
    (§20.3).
  - **обычные чипы:** nibble-split `DAT_007a39bc`
    (`0x15 = dl&0x0F`, `0x16 = dl&0xF0`, со спецслучаем `0xF0`).
- `0x17` не пишется никогда — мусор стека.

Это и есть давний пункт «порядок байт напряжения — в одном захвате»
(§28.4). Статически он теперь привязан к *какому* байту и *какому*
глобалу; захват добавляет только конкретное значение `DAT_007485c8`
для каждой из трёх UI-настроек VCCQ.

### 30.4 Поправки к таблице §20.2

1. `data_memory_size` (`DAT_007a39ac`) пишется **один раз, в 0x08** —
   «дубль в 0x04..06» из §20.2 был фантомом. `0x04` — это
   `DAT_007a39bc` (cfg).
2. `0x05` (`DAT_007a39bd`) в §20.2 **отсутствовал**.
3. `0x2c` — это **u16 zero-extended**, а не нативный u32.
4. Блок 0x30..38 был перепутан: `DAT_007a39d0` (i32) — в **0x30**
   (§20.2 говорил 0x34..38); `DAT_007a3ba4` — в **0x34** (§20.2: 0x30);
   `DAT_007a39be` (байт→word) — в **0x36** (§20.2: 0x32).
5. `0x3c..3f` — **не** сплошной padding: `0x3c=0`, `0x3d=0`,
   `0x3e=мусор`, `0x3f=DAT_007a39a9`.

`build_begin_transaction()` в прототипе обновлён под эту карту: теперь
заполняет только `0x00/0x01/0x02/0x08/0x0a/0x10` (стабильные поля из
per-chip БД), а `0x03..08` и `0x14..3f` оставляет нулями под захват.

## 31. Первая сессия с железом — живая проверка по USBPcap

Это **первая секция, подтверждённая реальным трафиком устройства** (уже
не только статика). Сняты два USBPcap-захвата в день приезда T48
(2026-05-29) под родным Xgpro на Windows:

- короткий захват **подключения / версии** (20 пакетов) и
- полный захват **System Self-check** (1422 пакета, 9.1 с).

Устройство представилось так: версия прошивки **`00.01.39`** (как это
декодируется — см. §31.1), build-stamp **`2024-08-15 17:21`**, модель
T48. Энумерация прошла на **high-speed USB 2.0 (480 Мбит/с)** ровно с
**четырьмя bulk-эндпоинтами** — `0x01`/`0x81` и `0x02`/`0x82`, все с
`wMaxPacketSize = 512` — что **напрямую подтверждает карту эндпоинтов из
§2** (EP1 — короткие команды, EP2 — bulk). Лог подключения самого Xgpro
согласуется: `Device 1: T48 [TL866-3G] Ver: 00.01.39, USB POWER 04.89 В,
USB2.0 HS 480 МГц` (обрати внимание на маркетинговое имя Xgpro
**TL866-3G** против «TL866II Plus» из базы USB-ID).

> Про захват прошивки: в нём **нет firmware-payload**. Реальный флеш
> переводит TL866/T48 в **bootloader, который ре-энумерируется** (может
> под другим идентификатором), поэтому фильтр USBPcap, привязанный к
> `a466:0a53`, блоки прошивки не увидит. Чтобы поймать настоящее
> обновление — захватывай **весь root-hub**, а не устройство. Ровно это
> здесь и произошло: оператор *обновил* прошивку, версия сменилась
> **`00.01.03` → `00.01.39`** (видно в ответе `0x00`, §31.1), но сами
> блоки флеша ушли на bootloader-устройство и **отсутствуют в этом
> захвате с фильтром `a466:0a53`** — наглядное подтверждение оговорки про
> фильтрацию.

### 31.1 Хендшейк identify / версия — top-opcode `0x00` (новый)

Раньше не было в таблице §3. При подключении Xgpro шлёт **8-байтный
нулевой пакет** на EP1 OUT и читает 63-байтную info-запись с EP1 IN:

```
host → EP1 OUT (8):  00 00 00 00 00 00 00 00
dev  → EP1 IN (63):  00 01 30 00 27 01 07 00            ; 8-байтный заголовок
                     "YYYY-MM-DDHH:MM" 00                ; дата сборки прошивки, NUL-terminated
                     "<32-символьный серийник>" 00       ; серийник экземпляра (здесь отредактирован)
                     E7 05 00 00 01 00 00                ; хвостовое слово + флаги — см. ниже
```

- Байт заголовка **`[6] = 0x07`** = **модель программатора** — совпадает с
  §29.1 (`DAT_0080109b`: 7 = T48). Та же тройка `… 01 07 00` встречается в
  ответах `READ_PINS`/`MEASURE_VOLTAGES` ниже, т.е. **байт[6] любого
  EP1-ответа несёт код модели**.
- **Версия прошивки — это `byte[0].byte[1].byte[4]` в десятичном виде.**
  Здесь `00 . 01 . 0x27` → **`00.01.39`**, ровно как Xgpro печатает в
  логе подключения (`Device 1: T48 [TL866-3G] Ver: 00.01.39`). `byte[4]` —
  номер сборки; читается **`0x27` (39) стабильно** при чтениях подряд.
- **Прошивка, которую накатил оператор, реально применилась.** В захвате
  *до* обновления (сразу после холодного подключения) `byte[4] = 0x03`
  (= `00.01.03`); после обновления — `0x27` (= `00.01.39`). То есть по
  `0x00` identify версию *определить можно* — сам трафик флеша по-прежнему
  ушёл на ре-энумерированный bootloader, который захват с фильтром по
  `a466:0a53` не видит (врезка в начале §31 в силе), но **дельта версии
  до/после подтверждает, что обновление прошло.**
- Строка даты сборки (`2024-08-15 17:21`) при обновлении **не менялась** —
  это фиксированный build-stamp данной линейки прошивки, а не
  пользовательская версия; версия живёт в `byte[4]`.
- Хвостовое 16-битное слово — это **НЕ версия**, а **живой ADC-подобный
  замер**. При чтениях подряд вернулось `0x05E7 / 0x05ED / 0x05E9 /
  0x05EC` (≈1511–1517), а раньше `0x05D1` (1489): дрожь в несколько
  отсчётов, т.е. аналоговое значение в момент identify. (Это исправляет
  ранний черновик, где это слово ошибочно приняли за версию.)
- Сразу после идут `0x3D` (`SWITCH`, с 8-байтным магиком
  `23 01 67 45 AB 89 EF CD`) и `0x3F` (`RESET`) — оба согласуются с
  именами из §3.

### 31.2 System Self-check — живая расшифровка (подтверждает и правит §22.8)

Self-check использует **только EP1** (без EP2 / eMMC), что подтверждает:
он безопасен с пустым socket'ом. Кадрирование команд в проводе — это
документированные 8 байт `[op][00 00 00][u32 arg LE]`; сеттеры пин-
паттернов используют 24-байтную форму. Видны три фазы, в таком порядке:

1. **walk `SET_OUT`** — для индекса `N = 0,1,2,…`: `0x36` (выбор, arg=N) →
   `0x35` `READ_PINS` → `0x31` `SET_PULLUPS` (отпустить).
2. **walk `SET_GND`** — `0x30` (24-байтный one-hot паттерн пинов) → `0x35`
   `READ_PINS`.
3. **Напряжения / статус** — `0x33` `MEASURE_VOLTAGES` → 24-байтный ответ;
   `0x39` `REQUEST_STATUS` → 32-байтный ответ; обрамлено `0x2D`
   `RESET_PIN_DRIVERS` в самом начале и конце.

**Ответ `READ_PINS` (`0x35`) — 16 байт, а не 40** (это правит «recv 40B»
из §22.8, шаг 4c):

```
35 00 10 00 27 01 07 00   <6-байтная битмаска пинов>   57 00
└─ echo + заголовок (8) ┘  └─ pins[8..14) ──────────┘   └ хвост
```

48-битная маска — доказательство **теста бегущим битом**: при подаче на
индекс `N` обратно читается **ровно сброшенный бит `N`**, остальные
выставлены — `N=0 → FE`, `1 → FD`, `2 → FB`, `3 → F7`, … `7 → 7F`,
`8 → FF FE`, `9 → FF FD`, … То есть `READ_PINS` возвращает 6-байтную
(48 пинов) битмаску с offset 8, **а не** массив `reply[8..48]`, как
предполагала §22.8.

**Ответ `MEASURE_VOLTAGES` (`0x33`) — 24 байта:** тот же 8-байтный
заголовок (`33 00 10 00 27 01 07 00`), затем **четыре `u32` LE замера по
линиям**. Один здоровый idle-сэмпл: `1251, 1492, 1241, 2020` (сырые
единицы — мВ это или отсчёты АЦП, пока TBD, один калиброванный захват
вопрос).

**Ответ `REQUEST_STATUS` (`0x39`) — 32 байта**, все нули на здоровом
idle-селф-тесте.

### 31.3 Что эта сессия подтвердила / поправила / добавила

- **Подтверждено:** карта эндпоинтов §2 (4 bulk EP, 512 Б); имена опкодов
  minipro `0x2D/0x2E/0x2F/0x30/0x31/0x32/0x33/0x35/0x36/0x39`, несущие
  ровно ожидаемые байты; байт модели из §29.1 (`7` = T48), теперь видимый
  как байт[6] любого EP1-ответа.
- **Поправлено против §22.8:** ответы `READ_PINS` — **16 Б, не 40 Б**;
  результат по пинам — **6-байтная битмаска с offset 8**, а не
  `reply[8..48]`; наблюдаемый порядок фаз — walk SET_OUT → walk GND →
  напряжения/статус.
- **Новое:** top-opcode **`0x00` = device identify** (дата сборки +
  серийник + хвостовое динамическое слово, §31.1); стабильная форма
  заголовка EP1-ответа `… 01 07 00` с кодом модели в байте[6].

### 31.4 Живой прогон `first_contact.py` — idle read-back'и (без чипа, без bitstream)

Прогон безопасного пробника прототипа на устройстве (connect → identify
→ measure_voltages → request_status → read_pins; ни один не подаёт
программирующее напряжение) воспроизвёл форматы выше и добавил:

- **Шкала `MEASURE_VOLTAGES` (`0x33`) верна.** Коэффициенты из minipro
  дают вменяемые idle-рейлы: **`vusb ≈ 4.976 В`** (шина USB 5 В — чистый
  sanity-чек), `vpp ≈ 11.14 В`, `vcc ≈ 3.37 В`, `vccio ≈ 3.26 В`. Значит,
  `0x33` отдаёт реальные данные АЦП **даже без загруженного test-bitstream**.
- **idle-ответ `READ_PINS` (`0x35`)** = 16-байтный блок
  `35 00 10 00 27 01 07 00` + **нулевая** 6-байтная маска — т.е. без
  загруженного драйвер-bitstream ни один пин не выставлен (как и ожидалось).
  Подтверждает размер 16 байт и маску с offset 8 из §31.2.
- **`REQUEST_STATUS` (`0x39`)** без активной сессии = **32 нулевых байта**,
  бит OVC сброшен — безопасный idle-базис.

Все четыре эндпоинта, запись identify и эти read-back'и воспроизводимы из
Linux через libusb без udev-правила на этом хосте (узел устройства уже
несёт uaccess-ACL).

## 32. Classic-чип чтение / стирание / запись — полный цикл из Linux

Первое **сквозное чтение *и* запись** реального чипа: и захвачено из
Xgpro, и **воспроизведено байт-в-байт нашим pyusb-прототипом на Linux**.
Цель — **93LC56** (3-проводный Microwire EEPROM, 256 байт), конфиг-EEPROM
платы **FT2232**, читался/писался **внутрисхемно** через ICSP-порт
(`ICSP_VCC Enable`). Содержимое: FTDI `VID 0x0403 / PID 0x6010`, строки
`"USB <-> Serial Converter"` и т.д.

### 32.1 Кадрирование сессии — `BEGIN_TRANSACTION` на реальном чипе (валидирует §30)

```
03 02 8b 81 00 00 00 6c  00 00 00 00 0a 00 00 00
00 01 00 00 00 00 00 00  ... (64 байта)
```
- `byte[0x01] = 0x02` → protocol_id для 93-серии;
- `byte[0x02..03] = 8b 81` → variant чипа;
- `byte[0x10] (u32 LE) = 0x00000100 = 256` → **`code_memory_size` = размер
  чипа**, ровно по карте полей §30. Первое подтверждение на живом чипе.

`REQUEST_STATUS` (`0x39`) шлётся до/после каждой фазы: 32-байтный ответ,
**OVC в byte[12]** (здесь чисто).

### 32.2 `READ_CODE` (`0x0D`) — чтение, EP2 IN

```
EP1 OUT (8):  0d 01 40 00 [word_addr LE32]      ; 0x40 = кусок 64 байта
EP2 IN (64):  <данные>
```
Четыре вызова по word-addr `0x00 / 0x20 / 0x40 / 0x60` → 256 байт. Данные
приходят на **EP2 IN (`0x82`)**.

### 32.3 `ERASE` (`0x0E`) + `WRITE_CODE` (`0x0C`) — цикл программирования, EP2 OUT

Полное *программирование* в Xgpro — это **read → erase → write →
verify-read**:

```
ERASE:        EP1 OUT (8):  0e 00 01 00 00 00 00 00
WRITE_CODE:   EP1 OUT (8):  0c 01 20 00 [word_addr LE32]   ; 0x20 = кусок 32 байта
              EP2 OUT (32): <payload>
```
Восемь кусков записи по word-addr `0x00 / 0x10 / … / 0x70` → 256 байт.
**Асимметрия:** запись — кусками по **32 байта** (`byte[2]=0x20`), чтение —
по **64 байта** (`byte[2]=0x40`). Payload записи идёт на **EP2 OUT
(`0x02`)**.

### 32.4 EP2 двунаправлен и для classic-чипов (правит §2)

В `§2` стояло «EP2 IN: not observed». Этот захват опровергает это и для
**classic**-пути (для eMMC было известно, §19.4): **EP2 IN = bulk-чтение,
EP2 OUT = bulk-запись** для обычных `READ_CODE`/`WRITE_CODE`, не только
eMMC.

### 32.5 Воспроизведено из Linux

Прототип (`examples/t48_emmc.py`, низкоуровневые `ep1_send`/`ep1_recv`/
`ep2_send`/`ep2_recv`) повторил всё на живом устройстве:

1. **Чтение** — 256 байт идентично захвату Xgpro (FTDI VID/PID + строки).
2. **Запись** — записал маркер-кусок, прочитал обратно без изменений.
3. **Восстановление** — прогнал канонический цикл из захвата (`ERASE` +
   восемь 32-байтных `WRITE_CODE`), вернув оригинальный FTDI-образ;
   verify-чтение дало **байт-в-байт golden-образ** (OVC чист всё время).

Это первое подтверждение, что реверс classic-транспорта поддерживает
**полный цикл read-modify-write-verify из Linux**, совпадая с родным
Xgpro на проводе.

## 33. eMMC-ISP через адаптер — полное чтение+verify (главная цель проекта)

Тот самый захват, ради которого всё затевалось: **внутрисхемное чтение
eMMC в режиме 4-бит / 3.3 В через ISP-адаптер XGecu** — **boot-разделы +
RPMB + 128 МБ user area**, затем **проход проверки (verify)**. 42 тыс.
пакетов, ~150 МБ на EP2 IN. Подтверждает почти весь §7–§30 на живом
кристалле и впервые показывает **канал адаптера** и **init-хендшейк
eMMC**, которые были помечены TBD.

### 33.1 Канал адаптера — top-opcode `0x24` (разрешает §27/§28)

ISP-адаптер управляется через **отдельный top-opcode `0x24`** (а не
`0x2B`, который §28.1 уже отозвал). Саб-опкоды: `0xe0`, `0xf0`, `0xf1`.
В ответе — строка-идентификатор адаптера:

```
host → 0x01 OUT:  24 f0 00 00 01 00 00 00
host → 0x01 OUT:  24 e0 28 00 00 ... e5
dev  → 0x81 IN :  24 00 10 00 00 08 00 00  "XGecu Directly" 00…  09 00 a0 ad
```

То есть внутрисхемный адаптер представляется как **`XGecu Directly`**.
Следом идёт опкод `0x3E` (новый) с 16-байтным статус-ответом
(`3e 00 10 00 …ff 57 00`) — то же семейство статусов с хвостом `…57 00`,
что у `READ_PINS`.

### 33.2 Init-хендшейк eMMC (был TBD)

По порядку, до любой bulk-передачи:

| Шаг | EP1 OUT | Ответ | Смысл |
|-----|---------|-------|-------|
| BEGIN | `03 31 00 00 00 05 a1 00 …` | — | **`protocol_id = 0x31` (eMMC)** ✓, `data_memory_size@0x08 = 32`, `code_memory_size@0x10 = 512` |
| status | `39 31 00 00 00 05 a1 00` | 32 Б нулей | OVC чист |
| init | `21 00 00 00 00 00 00 00` | `21 00 00 00 80 80 ff c0` | algorithm/init → OCR-подобное `80 80 ff c0` |
| READID | `05 00 00 00 …` | `07 …80 80 ff c0` **CID** `44 00 01 45 30 30 34 47 39 …` | **CID**, PNM ASCII `"E004G9"` |
| READ_USER | `06 00 00 00 …` | 24 Б (`…32 00 0f d0 ff 03 …`) | CSD / статус карты |
| EXT_CSD | `08 48 00 02 00 00 00 00` | 512 Б на EP2 IN + 8 Б ack | `0x08`/`0x48` single-block (EXT_CSD) |
| SWITCH ×4 | `27 46 …` | `27 00 10 00 00 08 00 00` | CMD6 (см. §33.3) |
| CMD30 | `08 5e 04 00 …` | — | обёртка §26.2 |

`0x05`/`0x06` переиспользованы из classic-набора, чтобы отдать CID и CSD;
`0x21` — eMMC-специфичный init.

### 33.3 CMD6 SWITCH = селектор раздела (валидирует §7/§24 байт-в-байт)

Каждый SWITCH — это `27 46 00 00 00 [val] b3 [access]`, т.е. **запись
EXT_CSD[179] `PARTITION_CONFIG`** (`0xb3 = 179`) значением `[val]`,
младшие 3 бита которого выбирают аппаратный раздел:

| Байты команды | val | раздел |
|---------------|-----|--------|
| `27 46 00 00 00 01 b3 01` | 1 | **BOOT1** |
| `27 46 00 00 00 02 b3 01` | 2 | **BOOT2** |
| `27 46 00 00 00 03 b3 01` | 3 | **RPMB** |
| `27 46 00 00 00 07 b3 02` | clear | **USER** (CLEAR_BITS 0x07) |

`27 46 00 00 00 03 b3 01` и `27 46 00 00 00 07 b3 02` — это **в точности**
байты, которые шлёт `cmd_A(SWITCH→RPMB)` / `cmd_A(SWITCH→USER restore)`
прототипа: кодировка SWITCH из §7/§24 подтверждена на железе.

Сессия идёт так: `→RPMB → →USER → →BOOT1 [read] → →BOOT2 [read] → →RPMB →
→USER [read 128 МБ]`, затем **проход verify** повторяет `→BOOT1 → →BOOT2
→ →RPMB → →USER`. Это и есть операция «системные разделы + 128 МБ user
area, потом проверка».

### 33.4 Bulk-чтение — setup `0x0D` + стрим `0x14`/`0x15` → EP2 IN

Каждое чтение раздела задаётся **40-байтным дескриптором `0x0D`**, напр.:

```
0d 01 00 00 | 00 00 00 00 | 00 02 00 00 | 20 00 00 00 | 00 01 00 00 |
20 00 00 00 | 20 00 00 00 | 01 00 00 00 | 01 00 00 00 | 00 00 00 00
```
(стартовый LBA, размер блока `0x200`, и поле длины/количества, которое
масштабируется под объём чтения — `0x0100` для маленьких boot-чтений и
`0x2000` для 128 МБ user). Затем данные стримятся **514 парами
`0x14`(setup)/`0x15`(trigger)** по 16 байт, а payload приходит на **EP2
IN (`0x82`)** USB-трансферами по **16 КБ и 32 КБ** — ~150 МБ за чтение +
verify.

### 33.5 Что это закрывает

- **Канал адаптера = `0x24`**, идентификатор `XGecu Directly` — недостающий
  кусок §27/§28.
- **Полный init-хендшейк eMMC** (`0x21`/`0x05`/`0x06`/`0x08·0x48`), ранее
  TBD, теперь — конкретная последовательность с реальными ответами (CID,
  CSD, OCR-подобное слово).
- **Карта разделов CMD6 SWITCH** (BOOT1/BOOT2/RPMB/USER через
  `PARTITION_CONFIG`) подтверждена, и наша байтовая кодировка SWITCH
  совпадает с проводом точно.
- **Bulk-чтение eMMC идёт по EP2 IN** в объёме (~150 МБ), через `0x0D` +
  `0x14`/`0x15`.

Для *нашего* прототипа всё ещё нужен адаптер (канал `0x24`
аутентифицируется к адаптеру), но протокол больше не догадки — это
референс-захват для реализации eMMC-ISP чтения на стороне Linux.

### 33.6 Ширина шины (1-бит vs 4-бит) — это host-side байт в `BEGIN`, а не CMD6-свитч

Сравнение 4-бит/3.3В захвата выше с **1-бит, 64 МБ** чтением *того же*
eMMC (тот же CID `…E004G9`, тот же адаптер, та же прогулка по разделам):
два пакета `BEGIN_TRANSACTION` отличаются **ровно двумя байтами**:

| offset | 1-бит | 4-бит | смысл |
|-------:|:-----:|:-----:|-------|
| `0x0c` | `0x51` | `0x54` | селектор algo / ширины шины |
| `0x3f` | `0x51` | `0x54` | то же значение, дублируется (`DAT_007a39a9`, §30) |

`0x51` / `0x54` — это algo-номера `.alg` **`EMMC_51` (1-бит)** и **`EMMC_54`
(4-бит)**, т.е. FPGA-битстрим, который бит-бэнгает шину eMMC. Важно:
**ни в одном захвате нет CMD6 `BUS_WIDTH`-свитча** (`EXT_CSD[183]`, index
`0xb7`): набор SWITCH идентичен (только `PARTITION_CONFIG`). Значит ширина
шины данных выбирается **целиком host-side** — выбором битстрима в
`BEGIN[0x0c]/[0x3f]`, а самому eMMC `BUS_WIDTH` менять не командуют.

Следствие для карты §30: `BEGIN[0x0c]` (младший байт поля «page_size») и
`BEGIN[0x3f]` (`DAT_007a39a9`) вместе несут **код algo/ширины шины** и
перекрывают variant-букву из per-chip БД — в этих ISP-чтениях байты
`variant [0x02..03]` равны `00 00`, а живой селектор — `0x51`/`0x54`.
1-бит чтение и по проводу ~в 1.6× медленнее (61 с против 37 с; ~100 МБ
против ~150 МБ на EP2 IN), как и ожидается для узкой шины.

## 34. eMMC-ISP запись — erase → program → verify (захвачено)

Захват **1-бит записи eMMC в user area** (тот же чип/адаптер, что в §33)
замыкает round-trip: показывает, как работает *программирование* eMMC, и
оно **структурно отличается от чтения**.

Init идентичен (§33.2): `0x24` адаптер (`XGecu Directly`) → `0x3E` → `0x03`
BEGIN (`protocol_id=0x31`, bus-width `0x51`) → `0x21`/`0x05`/`0x06`/
`0x08·0x48` → SWITCH `→USER` (`27 46 00 00 00 07 b3 02`). Примета: у
write-`BEGIN` **`byte[0x18] = 0x04`**, тогда как у чтения было `0x03` —
вероятный маркер режима read/write.

### 34.1 Фаза ERASE — `0x0E` + `0x27/0x4D`, группами по 512 КБ

Целевой регион сначала стирается, как **32 итерации**:

```
EP1 OUT:  27 4d 01 00 00 00 00 01 00          ; 0x27 sub-op 0x4D (setup группы стирания)
EP1 OUT:  0e 00 00 00 [start_blk LE32] ff [end_lo] 00 00 00 00 00 00
EP1 IN :  0e 00 00 00 80 80 ff c0             ; OCR-подобный ack
```
`start_blk` шагает по `0x400` (1024 блока) — `0, 0x400, 0x800, …` — а поле
`ff XX` — соответствующий end-маркер группы (`ff03, ff07, ff0b, …`).
**32 × 1024 блока × 512 Б = ровно 16 МБ** стёрто — совпадает с задуманным
объёмом записи. То есть `0x0E` несёт `(start, end)` блочные адреса (а не
1-shot форму `0e 00 01 …` из §32), а `0x27/0x4D` — спутник на каждую
группу (разрешает вопрос §25 «`0x4D` = commit/finalize?» — это **шаг
группы стирания**).

### 34.2 Фаза WRITE — setup `0x1F` + payload на EP2 OUT

Запись eMMC **не** использует пары `0x14`/`0x15` чтения. Вместо этого
новый опкод **`0x1F`** несёт 40-байтный дескриптор (зеркало `0x0D`-
дескриптора чтения):

```
1f 01 00 00 | [addr] | 00 02 00 00 | 20 00 00 00 | [count] |
20 00 00 00 | 20 00 00 00 | 04 00 00 00 | 01 00 00 00 | 00 00 00 00
```
(заметь поле `04 00 00 00` там, где у `0x0D`-чтения было `01 00 00 00`).
Payload затем стримится на **EP2 OUT (`0x02`)** кусками по **16 КБ**
(трансферы 16400 Б = 16384 данных + 16). Здесь вылилось ~8.6 МБ — стирание
покрыло все 16 МБ, но по проводу прошло ~8.6 МБ payload (Xgpro, скорее
всего, **пропускает пустые/0xFF страницы**; точная политика TBD).

### 34.3 Фаза VERIFY

После программирования Xgpro читает регион обратно путём §33.4 (`0x0D` +
EP2 IN, ~25 МБ включая прогулку по boot/RPMB) и сверяет — это и есть
«write + verify» из названия операции. Одиночный `0x0A` (generic eMMC CMD
wrapper, §23.1) появляется ближе к концу как финальный статус/CMD.

### 34.4 Сводка: опкоды чтения vs записи

| Фаза | Чтение | Запись |
|------|--------|--------|
| bulk setup | `0x0D` (40 Б) | **`0x1F`** (40 Б) |
| bulk-данные | `0x14`/`0x15` → **EP2 IN** | напрямую → **EP2 OUT** (16 КБ) |
| стирание | — | **`0x0E` (start,end)** + `0x27/0x4D` ×N |
| `BEGIN[0x18]` | `0x03` | `0x04` |

С этим **чтение и запись** eMMC-ISP оба захвачены и расшифрованы —
протокольная часть проекта по сути завершена; остаётся on-device
аутентификация адаптера (мимо провода) и превращение этих флоу в методы
прототипа.

## 35. eMMC-ISP чтение/запись реализованы и проверены из Linux

`examples/t48_emmc_isp.py` реплеит флоу §33–§34 с параметром адреса блока,
и **произвольные чтение И запись проверены на живом железе из Linux** (без
Xgpro): 16 КБ-паттерн, записанный в произвольный блок, читается обратно
байт-в-байт и сохраняется между сессиями. По ходу реализации уточнились
детали, которые сырые захваты лишь подразумевали.

### 35.1 Read-«arm» — это 512-байтная RPMB-проба

Перед первым `0x0D`-чтением Xgpro делает одноразовую последовательность,
без повтора которой bulk-движок не стримит:

```
SWITCH->RPMB (27 46 00 00 00 03 b3 01)   ; EP1, 8-байт ответ
0x14  (14 00 00 00 00 00 00 00 01 00 00 02 00 00 00 00)   ; EP1
512 байт 0x00                             ; EP2 OUT
0x15  (15 00 00 02 00 00 00 00 01 00 00 02 00 00 00 00)   ; EP1
512 байт + 16 байт                        ; EP2 IN (ответ RPMB + статус)
SWITCH->USER (27 46 00 00 00 07 b3 02)    ; EP1, 8-байт ответ
```

### 35.2 Точное кадрирование bulk-чанков

- **READ** (`0x0D` setup: byte[4..8]=стартовый блок, byte[16..20]=число
  чанков): каждый 16 КБ-чанк приходит на EP2 IN как **`[16-байт заголовок +
  16368 данных]`**, затем отдельный **`[16-байт хвост]`** — склеиваем
  `header[16:] + tail` → полные 16384 байта данных.
- **WRITE** (`0x1F` setup): payload идёт на EP2 OUT 16 КБ-чанками, у каждого
  **16-байтный заголовок** `struct <u32 0><u32 block_addr><u16 512><u16 0>
  <u32 32>`. Именно `block_addr` в заголовке даёт и пропуск нулей, и
  произвольную адресацию.
- **EXT_CSD** (`0x08`/`0x48`) отдаёт 512-байтный блок **и** 8-байтный ack —
  оба на **EP2 IN**.

### 35.3 Выбор VCCQ — `BEGIN[0x15]` (статический реверс)

В eMMC-ветке билдера `FUN_00444bc0` (`0x444edd`): `buffer[0x15] =
DAT_007485c8`. Во всех захватах он `0x00`; cmp-сайты (`0x4953a0`, рядом
*«50 MHZ (VCCQ=3.3V)»* против *«AUTO MAX=160MB/s»*, и `0x493d61`) трактуют
его как **boolean — 0 = 3.3В/50МГц, ≠0 = 1.8В/HS200**. Итого:

| `BEGIN[0x15]` | VCCQ |
|:---:|---|
| `0x00` | **3.3 В** (подтверждено захватом, read+write проверены) |
| `0x01` | **1.8 В** (выведено из статики, **не** проверено на железе) |

`t48_emmc_isp.py --voltage {3.3,1.8}` ставит ровно этот байт; больше в
BEGIN между напряжениями ничего не меняется.

### 35.4 Практические заметки

- **Зависание:** любой трансфер с таймаутом посреди сессии заклинивает
  eMMC-стейт-машину программатора. `clear_halt` / `usb reset` **не** лечат
  жёсткий wedge — только физический replug. `_recover()` + retry в прототипе
  справляется с транзиентными сбоями init; при жёстком wedge кидается
  «replug the T48».
- Handshake адаптера (`0x24` → `XGecu Directly`) реплеится с ПК нормально:
  крипта идёт адаптер↔прошивка, ПК лишь повторяет захваченные байты
  (подтверждает §28.1 / §33.1).
- Проверенные операции на 3.3В / 1-бит: identify, CID/CSD/EXT_CSD,
  произвольное чтение, произвольная запись, персистентность между сессиями.
