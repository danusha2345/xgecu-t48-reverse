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
