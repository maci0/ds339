# JONSBO-AIO / MS Display SDK reverse engineering

Rounds 2–3. Artifacts under `~/.cache/ds339-cap/` (JONSBO-AIO Setup **2.8**,
`MSDISPLAYSDKWRRAPER.dll` PE32+ x64, build path
`D:\temp\MSDisplaySDK\MSDisplaySDKPackage\...`, linked **libjpeg-turbo 3.0.5**).

SDK version export `Wrraper_MSDisplayGetSDKVersion` returns **3.2.4.31**
(`3, 2, 4, 0x1F`). Matches Wine log: `MSDisplayStart V3.2.4.31`.

Live unit on this host: USB `345f:9132`, serial `2019BA7160B0`,
chip-id `@0xF000 = b7 16 0a` → product **`0x912C`**.

--------------------------------------------------------------------------------

## 1. Software stack

| Layer | File | Role |
|-------|------|------|
| UI app | `JONSBO-AIO.exe` | WPF/.NET (namespace `Vmax.*`), themes, sensors, encode loop |
| Helpers | `common.dll` | shared .NET utilities (not USB) |
| MS USB path | `MSDISPLAYSDKWRRAPER.dll` | native libusb0 + JPEG + raw frame builder |
| Alt USB path | `AicUsbDisplay.dll` | P/Invoke only (`AICDisp*`); **not shipped** in 2.8 payload |
| JPEG | `turbojpeg.dll` / `TurboJpegWrapper.dll` | app-side compress (`TJPF_BGRA`, etc.) |
| WinUSB bind | `MSUSBDisplay.inf` + `libusb0.sys` | binds **only** `VID_345F&PID_9132&MI_03` |

INF device class `MSDisplay`, GUID `{FB781AAF-9C70-4523-A5DF-642A87ECA567}`,
hardware ID `USB\VID_345F&PID_9132&MI_03`. Interface 0 (HID) stays with
hidclass; only vendor bulk MI_03 is claimed by libusb0. SDK claims iface **3**
only (`usb_claim_interface(..., 3)`).

App also has `CopyLibusb0(path)` to deploy the DLL next to the EXE.

### 1.1 Managed P/Invoke surface (`Vmax.Helper.DeviceApi`)

```
MSDISPLAYSDKWRRAPER.dll:
  Wrraper_MSDisplayStart(loglevel, edid*)
  Wrraper_MSDisplayStop()
  Wrraper_MSDisplayRegisterCallback(attach, detach)
  Wrraper_MSDisplaySetVideoParam(handle, MSDisplayTiming*)
  Wrraper_MSDisplaySendPicture(handle, MSDisplayPicture*, bool b)
  Wrraper_MSDisplayReadFlash / ReadSN / ReadXdata
  MSDisplayResume / MSDisplayPause   // note: not Wrraper_ prefixed in ImplMap
```

### 1.2 Native structs (managed layout)

```c
typedef struct { int Width; int Height; void *data; } MSDisplayPicture; // BGRA*
typedef struct { uint32_t width, height, refresh; } MSDisplayResolution;
typedef struct {
    /* full timing; SetVideoParam reads width@0 height@4 in our harness, but
       SDK internal uses hactive/vactive/vic/polarity/... (MSDisplayTiming) */
    uint32_t vic, polarity, htotal, vtotal, hactive, vactive;
    uint32_t pixclk, vfreq, hoffset, voffset, hsyncwidth, vsyncwidth;
} MSDisplayTiming;
typedef struct {
    int mode;
    /* edid_replace blob, append_count, timing_append */
} MSDisplayEdid;
```

`SendPicture(..., bool b)`:

- `b == true` **and** chip `jpeg_flag` set → JPEG encode path
- otherwise → raw builder (RGB888 or UYVY)

Themes for this panel: `Programme/339H01` / `ThemeScheme/339H01.json`
**Width=960 Height=376** (landscape wire buffer; physical panel is 376×960
portrait).

--------------------------------------------------------------------------------

## 2. Chip-id classifier (`fcn.18001f660`) — **includes our panel**

Clears `jpeg_flag` (`ctx+0x5A1`) and `product` (`ctx+0x28`), then:

1. `read3(0xFF00)` via `fcn.18001cc30` (B5 burst)
2. if no product match: `read3(0xF000)`
3. two more retries with `ctx+0x5A2=1` (same addresses)

Data bytes in the read buffer: `b0,b1,b2` = first three payload values.

| `b0 b1 b2` | `jpeg_flag` | product (`ctx+0x28`) |
|------------|-------------|----------------------|
| `?? 13 3A` | **1** | `0x9133` |
| `D7 13 0A` | **1** | `0x9132` |
| `!! 13 0A` (b0≠D7) | 0 | `0x9132` |
| **`B7 16 0A`** | **0** | **`0x912C`** |
| `A7 16 0A` | 0 | `0x912A` (`0x9133-9`) |
| `?? 16 0A` (other b0) | 0 | `0x9120` |
| `C5 12 ??` | **1** | `0x5120` |
| no match | 0 | 0 → fail |

**This host's panel (`b7 16 0a`) is classified as product `0x912C`, not
`0x9132`.** USB PID stays `9132`; the SDK product id is separate.

`0x912C` only appears inside this classifier (no later special cases). Behaviour
is the generic non-JPEG / non-`9132` path.

### 2.1 Gate register depends on product

Several sites:

```
cmp  dword [ctx+0x28], 0x9132
mov  edx, 0xF7E9
mov  eax, 0xF439
cmovne edx, eax          ; product != 9132  =>  use F439
call read1(edx)          ; fcn.18001d940
test bit0 of value       ; host-flushing / not-OSD
```

| product | OSD / host-flush gate |
|---------|------------------------|
| `0x9132` | **`0xF7E9`** bit0 |
| anything else (incl. **`0x912C`**) | **`0xF439`** bit0 |

Live on this unit after `A6 04 01` commit:

| reg | value |
|-----|-------|
| `0xF7E9` | `0x09` (bit0 **set**) |
| `0xF439` | `0x00` (bit0 **clear**) |

So the SDK's non-9132 gate (`F439`) does **not** follow our commit the way
`F7E9` does. Bulk can still work (we have been using `F7E9`), but this mismatch
is a prime suspect for flaky first-frame / worker-skip behaviour if the worker
honours `F439` for `912C`. Further capture against real Windows+device should
confirm whether anything writes `F439`, or whether JONSBO never exercises the
raw path on this SKU.

--------------------------------------------------------------------------------

## 3. Format byte (`A6 01`) selection — confirmed in code

`fcn` around `0x18001a909` (geometry commit path):

```
area = hactive * vactive
if area > 0xE1000:           fmt = 0x22
elif fallback (ctx+0x594):   fmt = 0x22
elif jpeg_flag (ctx+0x5A1)==0: fmt = 0x11   // RAW
else:                        fmt = 0x22   // JPEG-capable
```

Matches CAPTURE.md RESULT 4: **`0x11` = raw, `0x22` = JPEG**.

--------------------------------------------------------------------------------

## 4. `SendPicture` / frame builder (`0x18001f9f0`)

Entry from export: `Wrraper_MSDisplaySendPicture` → `0x180018360` → builder
`0x18001f9f0` with resolved `hactive` (`ctx+0x234`) / `vactive` (`ctx+0x238`).

### 4.1 JPEG vs raw (builder head `0x18001fb05`)

```
jpeg_flag = ctx+0x5A1
if jpeg_flag != 0 AND SendPicture.b != 0:
    height = (vactive + 7) & ~7
    JPEG encode (tj path, pixelFormat=8 = TJPF_BGRA) @ 0x18001ffc0 / 0x180020117
    bare JFIF on bulk EP4 + ZLP; size padded to %4
else:
    // raw
    if area > 0xE1000 OR fallback OR jpeg_flag:
        UYVY path (2 B/px + header/footer)   // 0x18001fd25
    else:
        RGB888 path (3 B/px + header/footer) // 0x18001fb9d
```

For **`0x912C`**: `jpeg_flag=0` always → never JPEG; for 960×376
(`area=360960 ≤ 0xE1000`) → **RGB888 raw**.

### 4.2 RGB888 packing (`fcn.180023660`)

Source stride 4 (BGRA). Per pixel:

```
dst[0] = src[0]  // B
dst[1] = src[1]  // G
dst[2] = src[2]  // R
```

Then whole pixel area: every `0xFF` byte → `0xFE`.

### 4.3 Header / footer (RGB888 @ `0x18001fcb1`)

```
header[0]   = 0xFF
header[1]   = jpeg_flag ? 0x02 : 0x00     // sbb/and trick on flag
header[2..4]= 0
header[5]   = (width >> 4) & 0xFF
header[6]   = ((height >> 8) & 0x0F) | ((width & 0x0F) << 4)
header[7]   = height & 0xFF

footer[0]   = 0xFF
footer[1]   = 0xC0 | header[1]
footer[2..7]= 0
```

Width/height here are the **resolved hactive/vactive** (same orientation as
`A6 01` / `A6 02`). For theme 960×376:

```
FF 00 00 00 00 3C 01 78  ...pixels...  FF C0 00 00 00 00 00 00
```

--------------------------------------------------------------------------------

## 5. Timing / resolution

### 5.1 `reg 0x31 == 4` force path

Resolver `0x18001c380`: if `ctx+0x1A0` (reg 0x31) == 4 → force
**720×480, mode 2**.

Live panel: `reg 0x31 = 0x06` → not forced.

### 5.2 Static table (`0x180099676`, 22-byte records)

Standard CEA-ish modes only (1920×1080 … 640×480, 720×576). **No 960×376 and
no 376×960.** Custom theme sizes rely on SetVideoParam bookkeeping + free
`A6 01/02` programming, not table match.

### 5.3 EDID-derived table

When `ctx+0x384 == 1`, walk `ctx+0x414` records (same 0x16 stride) for width /
height / ~60 Hz.

--------------------------------------------------------------------------------

## 6. Exports (complete)

```
Wrraper_MSDisplayFlashErase
Wrraper_MSDisplayGetDeviceInfo
Wrraper_MSDisplayGetDeviceList
Wrraper_MSDisplayGetSDKVersion      -> 3.2.4.31
Wrraper_MSDisplayInitFlashGpio
Wrraper_MSDisplayPause
Wrraper_MSDisplayReadEEPROM
Wrraper_MSDisplayReadFlash
Wrraper_MSDisplayReadSN
Wrraper_MSDisplayReadXdata
Wrraper_MSDisplayRegisterCallback
Wrraper_MSDisplayResume
Wrraper_MSDisplaySendPicture
Wrraper_MSDisplaySetVideoParam
Wrraper_MSDisplayStart
Wrraper_MSDisplayStop
Wrraper_MSDisplayWriteEEPROM
Wrraper_MSDisplayWriteFlash
Wrraper_MSDisplayWriteXdata
```

Imports from `libusb0.dll` only: `usb_init`, `usb_find_busses/devices`,
`usb_open/close`, `usb_claim/release_interface`, `usb_control_msg`,
`usb_bulk_write`, `usb_get_busses`.

--------------------------------------------------------------------------------

## 7. Implications for Linux driver (`ds339.py`)

1. **This panel is MS912C-class (chip `b7160a`)**: RAW RGB888 BGR, never JPEG.
   Defaulting to RAW is correct; JPEG bulk leaves the logo.
2. **SDK packs BGR** from BGRA (`fcn.180023660`) + FF→FE + header/footer.
   **Live 912C panel** (probe): wire byte0=G, byte1=B, byte2=R (order `gbr`).
   Pure R (byte2) still reads purple-ish on this LCD; G and B are clean.
   Driver default is therefore `gbr`, not SDK `bgr`.
3. **Gate register**: for product `912C` the SDK polls **`F439`**, not `F7E9`.
   We currently arm on `F7E9` (which does flip). Worth dual-checking both, and
   watching whether anything ever sets `F439` on real Windows traffic.
4. **960×376** is a free-form timing (not in the static table); mode byte 0 is
   acceptable when not reg31-forced.
5. Optional later: port `GetDeviceInfo` / `ReadSN` / flash helpers; alt
   `AicUsbDisplay` path only if that DLL appears in another installer.

--------------------------------------------------------------------------------

## 8. Product-specific register map (round 3)

Almost every runtime `cmp product, 0x9132` picks **one of two register
addresses** via `cmovne`. **`0x912C` always takes the non-9132 side.**

| Purpose | product `0x9132` | other (`0x912C`, …) | Code |
|---------|------------------|---------------------|------|
| Host-flush / OSD gate (bit0) | **`0xF7E9`** | **`0xF439`** | `0x18001a85f`, `0x18001c836` |
| Mem-freeze style status (bit3) | **`0xD042`** | **`0xF242`** | `0x18001c80x` |
| Flash/EDID block A | `0xFC60` | `0x1C10` | `0x18001a5b0` |
| Flash/EDID block B | `0xFC80` | `0x1C30` | `0x18001a603` |
| Extra 9132-only scrub | **`0xF01F`** read/modify | skipped | `0x18001a679` |
| Command-done poll (9132) | **`0x1026`** | (see 5120) | `0x18001e98e` |
| Command-done poll (5120) | — | `0xC515`/`C516`/`C517`/`C518` | `0x18001e9e4`… |
| Video GPIO select | `0xFB07` if reg31==5 else `0xF037` | non-9132 branch | `0x18001f571` |

### 8.1 Implications for this panel (`0x912C`)

1. SDK **never sets jpeg_flag** for `b7 16 0a` → raw RGB888 only.
2. Gate polled is **`F439` bit0**, not `F7E9`. Live Linux: after `A6 04 01`,
   `F7E9=0x09` but **`F439=0x00`**. Either the worker never sees “flushing” for
   912C under our sequence, or something else must set `F439` (not found as a
   direct write in the SDK; likely device-side when scanout really starts).
3. No other `0x912C`-only branches exist outside the classifier. 912C is just
   “not 9132, not 5120, jpeg=0”.

### 8.2 `hid9` flag (`ctx+0x5A2`)

All HID builders (`B5` read, `C5` write, `A6` cmds) check `ctx+0x5A2`:

- **0**: 8-byte report (what we use): `[opcode, ...]`
- **1**: 9-byte report: `[report_id=1?, opcode, ...]` with length bump

Set during chip-id retry path (`mov byte [rsi+0x5A2], 1` before third
`read3(0xFF00)`). Normal path for this device leaves it **0**.

--------------------------------------------------------------------------------

## 9. Bulk path (exact, only 2 call sites)

`usb_bulk_write` appears **exactly twice**, both in the same function
(~`0x18001c91d`…`0x18001ca04`):

```
// Preconditions:
//   ctx+0x5A0 == 1          // bulk-ready / worker armed
//   frame_w  == hactive     // [slot+0x1CC] vs ctx+0x234
//   frame_h  == vactive     // [slot+0x1D0] vs ctx+0x238
//   libusb handle non-null  // ctx+0x190

size = slot->size   // +0x1BC
buf  = slot->ptr    // +0x1C0

usb_bulk_write(handle, ep=0x04, buf, size, timeout=3000);   // 0xBB8
// on success:
usb_bulk_write(handle, ep=0x04, dummy, 0, timeout=3000);    // ZLP
```

No other bulk endpoints. Failure path logs and returns negative libusb code;
`-0x74` is special-cased. After 2 successful frames (`ctx+0x228`), an extra
path runs (re-arm / stats).

**Linux note:** SDK bulk timeout is **3000 ms**. Undersized host timeouts can
look like flaky first frames.

Geometry mismatch skips bulk entirely (error `0xFFFFFC18` style) — another way
to stay on the logo if `A6 01/02` dims ≠ frame dims.

--------------------------------------------------------------------------------

## 10. Device context map (partial)

| off | meaning |
|-----|---------|
| `+0x18` | connection state; SendPicture requires `== 3` |
| `+0x28` | product id (`0x912C` / `0x9132` / …) |
| `+0x1A0` | cached reg `0x31` |
| `+0x1A8` | video-armed (set after first good frames) |
| `+0x1B0` | frame index (xchg) |
| `+0x1B4` | double-buffer select (0/1) |
| `+0x1B8…` | two slot descriptors (size/ptr/state) |
| `+0x1BC` / `+0x1C0` | active frame size / pointer |
| `+0x1CC` / `+0x1D0` | last encoded width / height |
| `+0x228` | successful bulk count |
| `+0x230` | mode byte for `A6 02` |
| `+0x234` / `+0x238` | hactive / vactive |
| `+0x240` | EDID/custom resolution count |
| `+0x50` | mutex (lock/unlock around USB) |
| `+0x190` | libusb device handle |
| `+0x594` | force non-JPEG/UYVY fallback |
| `+0x5A0` | bulk worker ready |
| `+0x5A1` | jpeg_flag |
| `+0x5A2` | hid9 |

Double-buffer: SendPicture fills one slot (`state=1` → builder → `state=2`),
worker bulk-sends the ready slot. App can queue while previous frame drains.

--------------------------------------------------------------------------------

## 11. A6 command builders (confirmed)

| fcn | wire | meaning |
|-----|------|---------|
| `0x18001e800` | `A6 03 03 00…` | transfer mode 3 |
| `0x18001eab0` | `A6 01 hh_hi hh_lo vh_hi vl_lo fmt 00` | input rect + format |
| `0x18001eda0` | `A6 02 mode 00 hh_hi hh_lo vh_hi vl_lo` | output timing |
| `0x18001e640` | `A6 04 <dl> 00…` | commit (`dl=1` on) |

All go out as HID SET_REPORT `bmRequestType=0x21 bRequest=0x09 wValue=0x0300`
timeout 1000 ms. Payload length 8 (or 9 if hid9).

Read path `0x18001d940`: opcode **`0xB5`**, value in response payload (not the
echo address bytes when using the N-byte reader).

Write path `0x18001d0a0`: opcode **`0xC5`** (single-byte style; `B6` used
elsewhere for xdata).

--------------------------------------------------------------------------------

## 12. Managed app (`JONSBO-AIO.exe`) — round 3

| Type / method | Role |
|---------------|------|
| `Vmax.Helper.DeviceApi` | P/Invoke to all `Wrraper_MSDisplay*` |
| `Vmax.Helper.AicDeviceApi` | P/Invoke `AICDisp*` (DLL not in package) |
| `Vmax.Helper.DLSDevice.ConvertFromBgra8888` | CPU convert (833 B IL) before compress/send |
| `Vmax.Helper.DLSDevice.TurboJpegNativeCompressReuse` | app-side JPEG (quality path; 838 B IL) |
| `Vmax.Helper.DLSDevice.SaveLogoAsync` | write logo JPEG blob |
| `Vmax.ViewModel.MainWindowViewModel.MSDisplayStart` | start + EDID wiring |
| `Vmax.App.CopyLibusb0` | deploy `libusb0.dll` next to EXE |
| `MSDisplayPicture` | `{int Width, Height; void* data}` BGRA |
| `MSDisplayTiming` | full CEA-style timing fields |
| `TJPixelFormat` | includes `TJPF_BGRA=8` (matches native JPEG) |

Themes: `339H01` = **960×376** landscape wire. Physical panel still portrait
376×960; app draws landscape and lets the panel rotate in hardware / bezel.

Native SDK can JPEG-encode itself when `b=true` and jpeg_flag; the C# side
*also* has TurboJPEG — either path may feed already-compressed or BGRA into
`SendPicture` depending on code path (need a live Windows capture to see which
`b` and buffer type JONSBO uses for 339H01).

--------------------------------------------------------------------------------

## 13. How this was done

- `pefile` + Capstone on `MSDISPLAYSDKWRRAPER.dll` (exports, IAT xrefs,
  product `cmovne` pairs, bulk-only call sites, A6 builders, classifier)
- `dnfile` on `JONSBO-AIO.exe` (types, ImplMap, method RVAs for compress/convert)
- Live regs on `345f:9132` (`F7E9` vs `F439`)
- Cross-check `CAPTURE.md` / `CAPTURE_RAW.md`

### Wine harness (`wine-harness/`)

Stub capture confirmed for product **912C** (`B7 16 0A`):

- Polls **`F439`** (not F7E9) during bring-up  
- `SendPicture(b=0)` + solid RGB red → wire pixels **`00 00 FE`** (BGR)  
- Frame size `8 + W*H*3 + 8`, ZLP after bulk  
- Public API handle is callback **arg0** as `uint32_t`, not the `usb_open` value  

See `wine-harness/README.md`. Build with mingw (`./build.sh`); run `./run-stub.sh`.

### Still open (need real device + Windows or more stub work)

1. Does **`F439` bit0** ever go 1 on real 912C hardware (stub forces both gates)?  
2. JONSBO app path for 339H01: `b=true` vs `false`, 960×376 without reg31 force.  
3. Whether `AicUsbDisplay.dll` ships in another package.
