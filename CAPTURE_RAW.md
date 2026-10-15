# DS339 / MS9132 RAW-path wire capture (real 720x480 resolution)

Captured the same way as `CAPTURE.md`: the **real** `MSDISPLAYSDKWRRAPER.dll`
runs under wine against a **stub `libusb0.dll`** that logs every
`usb_control_msg` / `usb_bulk_write`. This run forces the **RAW (non-JPEG) path**
with a **resolvable real resolution** so an actual pixel frame is emitted, not the
degenerate empty frame from `stub_raw00.log`.

## How this run was produced (method (a) from the task)
Scratch dir `~/.cache/ds339-cap/`. New harness `harness_raw.c` (SetVideoParam
720x480, SendPicture 720x480 BGRA gradient, `b=0`). Stub configured via env:
- `DS339_CHIPID_B0=0x00` -> chip-id resp[3]=0x00 -> **jpeg flag (ctx+0x5A1)=0**, RAW path.
- `DS339_REG31=4` -> reg 0x31 reads 0x04 -> resolver `fcn.18001c380` **forces 720x480, mode 2**.
- reg 0x32 = 0x09 (connected+stable), 0xF7E9 bit0 = 0 at init -> 1 after `A6 04 01`.

Run: `WINEPREFIX=~/.cache/ds339-cap/pfx WINEDLLOVERRIDES="libusb0=n" DS339_CHIPID_B0=0x00 DS339_REG31=4 DS339_LOG='C:\ds339cap\stub_raw_real.log' wine harness_raw.exe`.
Full log: `~/.cache/ds339-cap/pfx/drive_c/ds339cap/stub_raw_real.log`.

The chip-id GET response was `B5 FF 00 00 13 0A 00 00` (resp[3]=0x00 => jpeg
flag 0), reg 0x31 read returned `04`, and the SDK emitted **`A6 01 02 D0 01 E0 11 00`**
(fmt byte = 0x11, the raw selector) -> a real pixel frame followed on EP4.

================================================================================

## RESULT 1 - the EXACT raw frame wire bytes (720x480)

Quoted verbatim from the log (`usb_bulk_write` to EP 0x04), first 32 bytes and
the last 16 bytes of the same buffer:

```
[75] BULK_WRITE ep=0x04 size=1036816
  first32: FF 00 00 00 00 2D 01 E0  00 00 FE 00 00 FE 00 00  00 FE 01 00 FE 01 00 FE  01 00 FE 02 00 FE 02 00
  last16 : ... FE FE FE FE FE FE FE FE  FF C0 00 00 00 00 00 00
[76] BULK_WRITE ep=0x04 size=0           <- ZLP (end of frame)
```

### Size / pixel format (this is NOT UYVY at this resolution)
- `size = 1036816 = 8 (header) + 1036800 (pixels) + 8 (footer)`.
- `1036800 = 720*480*3` -> **3 bytes per pixel = RGB888**, NOT 2-byte UYVY.
- The frame builder `fcn.18001f9f0` selects the pixel encoding by area:
  `area = width*height`; `area > 0xE1000 (921600)` -> UYVY (2 B/px), `else` ->
  RGB888 (3 B/px). 720x480 = 345600 <= 0xE1000 -> **RGB888**.
  **The DS339 panel's native 376x960 = 360960 is also <= 0xE1000, so on the real
  panel the raw path is RGB888 as well, never UYVY.** (UYVY only appears for
  modes larger than ~921600 px, which this panel never uses.)

### Pixel byte order = B, G, R (per row converter `fcn.180023660`)
Source is BGRA (4 B/px). The converter reads `[src+0]=B, [src+1]=G, [src+2]=R`
(stride 4, skips alpha) and writes `dst[0]=B, dst[1]=G, dst[2]=R`:
```
0x18002367c  movzx ecx,[rax-2]   ; B = src[0]
0x180023670  movzx edx,[rax-1]   ; G = src[1]
0x180023678  movzx r8d,[rax]     ; R = src[2]
0x180023684  mov [r9-5],cl       ; dst[0]=B
0x180023688  mov [r9-4],dl       ; dst[1]=G
0x18002368c  mov [r9-3],r8b      ; dst[2]=R   ; lea rax,[rax+4] (4-byte src stride)
```
So on the wire each pixel is **B G R**, i.e. the source BGRA order minus alpha.
First source pixel (B=0,G=0,R=255) emitted as `00 00 FE` (R clamped, see below).

### 0xFF -> 0xFE clamping: YES, every pixel byte
After conversion, a loop over all `area*3` pixel bytes replaces any `0xFF`
with `0xFE` (the `0xFF` marker is reserved for the header/footer):
```
0x18001fca2  cmp byte [rbx],0xff
0x18001fca5  jne ...
0x18001fca7  mov byte [rbx],0xfe   ; clamp FF -> FE
0x18001fcaa  inc rbx               ; over all area*3 bytes
```
This is why source R=0xFF appears as `FE` on the wire, and the trailing all-white
rows are `FE FE FE ...`. **Every byte value 0xFF in the pixel area is clamped to
0xFE.** (UYVY branch does the same clamp.)

### The 8-byte HEADER, decoded byte-by-byte
Wire header = `FF 00 00 00 00 2D 01 E0` for width=720 (0x2D0), height=480 (0x1E0).
Builder (RGB888 branch @ 0x18001fcb1; UYVY branch @ 0x18001ff01 is identical
layout). In the disasm **r14 = dest width = 720, r13 = dest height = 480** (loaded
from the resolved geometry: `r14d=[rsp+0x110]`, `r13d=[rsp+0x118]`).

| off | wire | source op | meaning |
|-----|------|-----------|---------|
| 0 | `FF` | `mov [r8],0xff` | frame-start marker |
| 1 | `00` | `al=-jpeg_flag; sbb dl,dl; and dl,2; [r8+1]=dl` | selector bit: **0x00** when jpeg_flag clear (raw), 0x02 when set |
| 2 | `00` | `mov word [r8+2],0` | zero |
| 3 | `00` | (high byte of the word) | zero |
| 4 | `00` | `mov [r8+4],0` | zero |
| 5 | `2D` | `ax=r14w; shr ax,4; [r8+5]=al` | **(width >> 4) & 0xFF** = 0x2D0>>4 = 0x2D |
| 6 | `01` | `ax=r13w; shr ax,8; and al,0xf; or al,(r14b<<4); [r8+6]=al` | **((height>>8)&0x0F) \| ((width&0x0F)<<4)** = 0x1 \| 0x0 = 0x01 |
| 7 | `E0` | `mov [r8+7],r13b` | **height & 0xFF** = 0xE0 |

### The 8-byte FOOTER, decoded
Written at `[r8 + area*3]` (= `[rcx+8]`/`[rcx+9]`... where `rcx=r8+pixelbytes`):
```
0x18001fd09  mov byte [rcx+8],0xff   ; footer[0]=0xFF
0x18001fd0d  mov byte [rcx+9],dl     ; footer[1]=dl|0xC0 (dl=0x00 raw,0x02 jpeg)
0x18001fd10  mov dword [rcx+0xa],0   ; footer[2..5]=0
0x18001fd1a  mov word  [rcx+0xe],0   ; footer[6..7]=0
```
Wire footer = `FF C0 00 00 00 00 00 00`.  byte1 = `0xC0 | selector` (0xC0 raw,
0xC2 if jpeg_flag set).

### CORRECTION to the driver's header formula
Our driver currently builds:
```
header = [FF, 00, 00, 00, 00, (height>>4), ((width>>8)&0x0F)|((height&0xFF)<<4), width&0xFF]
```
This is **WRONG: width and height are swapped.** The hardware-correct header is:
```
header = [0xFF,
          0x00,                                   # selector (0x02 if jpeg_flag)
          0x00, 0x00, 0x00,
          (width  >> 4) & 0xFF,                   # byte5
          ((height >> 8) & 0x0F) | ((width & 0x0F) << 4),   # byte6
          height & 0xFF]                          # byte7
footer = [0xFF, 0xC0, 0, 0, 0, 0, 0, 0]           # byte1 = 0xC0|selector
```
Byte-by-byte verdict vs the driver formula:
- byte0 `FF` : correct.
- byte1 : driver hard-codes 00; correct for raw (jpeg_flag=0). (0x02 only if jpeg flag set.)
- bytes2-4 `00`: correct.
- byte5 : driver uses `height>>4`; **WRONG, must be `width>>4`**.
- byte6 : driver uses `((width>>8)&0xF)|((height&0xFF)<<4)`; **WRONG, must be
  `((height>>8)&0xF)|((width&0xF)<<4)`** (note: it is `width & 0x0F`, only the low
  nibble of width, NOT `height & 0xFF`).
- byte7 : driver uses `width&0xFF`; **WRONG, must be `height&0xFF`**.
- footer: `FF C0 00 00 00 00 00 00` correct (for raw).

For the panel's real 376x960 (width=376=0x178, height=960=0x3C0) the correct
header would be:
```
byte5 = 0x178>>4      = 0x17
byte6 = (0x3C0>>8)&0xF | (0x178&0xF)<<4 = 0x3 | 0x80 = 0x83
byte7 = 0x3C0 & 0xFF  = 0xC0
=> header = FF 00 00 00 00 17 83 C0 ,  footer = FF C0 00 00 00 00 00 00
```
(The driver's swapped formula would instead emit `FF 00 00 00 00 3C 81 78`, which
encodes the wrong geometry and is a prime suspect for the black/garbled frame.)

================================================================================

## RESULT 2 - EVERY control write between Start and the first raw bulk frame

In order, exact 8 bytes (from `stub_raw_real.log`). `SET` = SET_REPORT
(0x21,0x09,0x0300,0). Register reads (`B5`) are SET+GET pairs; only the SET shown.

```
# open
usb_claim_interface(iface=3)

# chip-id (ONE pair) -> resp[3]=00,resp[4]=13,resp[5]=0A => 0x9132, jpeg_flag=0
SET  B5 FF 00 00 00 00 00 00        ; chip id @0xFF00

# status reads
SET  B5 00 31 00 00 00 00 00        ; reg 0x31 -> 0x04 (forces 720x480 mode 2)
SET  B5 00 30 00 00 00 00 00        ; reg 0x30 SDRAM type
SET  B5 F7 E9 00 00 00 00 00        ; 0xF7E9 is_osd_flushing (init: bit0=0)
SET  F5 00 1F E0 / E8 / F0 / F8     ; flash read 0x1FE0..0x1FFF (serial)

# init bring-up (fcn.18001a1e0)
SET  A6 07 01 02 00 00 00 00        ; set_power_on  ; poll 0xC454 done
SET  A6 05 00 00 00 00 00 00        ; set_video_on(0) ; poll 0x118D done
SET  B5 F0 37 .. / B6 F0 37 00      ; set_screen_on(0): RMW 0xF037
SET  B5 F1 60 .. / B6 F1 60 00      ; clear 0xF160 bit5 (reg0x31!=4 path also runs here)
SET  B6 F0 31 34 00 00 00 00        ; write 0xF031 = 0x34
SET  C5 B0 / C6 B0 00               ; init_flash_gpio (fcn.18001cec0)
SET  C5 A0 / C6 A0 04
SET  C6 C7 D1 / C6 C8 C0 / C6 CA 00
SET  B5 F0 1F .. / B6 F0 1F 10      ; 0xF01F APPEND-mode bits
SET  F5 00 FC 50 00 00 00 00        ; flash read 0xFC50 (custom timing)
SET  B5 F0 1F .. / B6 F0 1F 00      ; 0xF01F restore
SET  C5 B0 / C6 B0 3C               ; B0 = 0x3C
SET  C5 B1 / C6 B1 3C               ; B1 = 0x3C

# worker tick: detect display + push geometry + switch to host scanout
SET  B5 00 32 00 00 00 00 00        ; reg 0x32 hotplug -> 0x09 (connected+stable)
SET  B5 F7 E9 00 00 00 00 00        ; re-check flushing
SET  A6 03 03 00 00 00 00 00        ; set_transfer_mode 3
SET  B5 10 26 00 00 00 00 00        ; status read
SET  A6 01 02 D0 01 E0 11 00        ; INPUT RECT + FORMAT  (fmt=0x11 RAW)
SET  B5 11 23 00 00 00 00 00        ; status read
SET  A6 02 02 00 02 D0 01 E0        ; OUTPUT TIMING (mode 2, 720x480)
SET  B5 11 25 00 00 00 00 00        ; status read
SET  A6 04 01 00 00 00 00 00        ; COMMIT / "input updated" -> flips 0xF7E9 bit0 -> 1

# ---- first raw frame ----
BULK ep=0x04 size=1036816  FF 00 00 00 00 2D 01 E0 ... pixels ... FF C0 ...
BULK ep=0x04 size=0                                        ; ZLP
```

### Is there an OSD / boot-logo / input-source-select write?  NO separate one.
The RAW control sequence is **byte-for-byte identical to the JPEG sequence**
(`stub_geom.log`) **except the single `A6 01` fmt byte (0x11 raw vs 0x22 jpeg)**.
There is **no extra OSD-disable register, no D042/F242 write, no input-source
toggle** emitted in the raw path that the JPEG path lacks. The panel leaves the
boot logo and shows host content purely via the A6 command chain:

  `A6 07 01` (power on) -> `A6 05 00` (video off) -> screen/F160/F031/flash-gpio
  init -> `A6 03 03` (transfer mode 3) -> **`A6 01 .. 0x11`** (input rect + RAW
  fmt) -> **`A6 02 ..`** (output timing) -> **`A6 04 01`** (commit).

`A6 04 01` is the write that flips reg `0xF7E9` bit0 from 0 (OSD/logo / not
flushing) to 1 (host fill / flushing). That bit transition IS the "leave the
logo, show host input" event. There is no dedicated OSD-layer register; the OSD
(boot logo) is whatever the controller scans out while `0xF7E9` bit0 == 0, and
the host frame replaces it once bit0 == 1 and frames are draining EP4.

The per-frame re-arm that lands AFTER the first frame is the only additional
device-state write, and it is also identical to JPEG:
```
B6 F0 37 01 00 00 00 00     ; screen_on  (0xF037 = 0x01)
A6 05 01 00 00 00 00 00     ; set_video_on(1) ; poll 0x118D done
```

================================================================================

## RESULT 3 - per-frame loop in the raw streaming path

Each `SendPicture` -> exactly one big bulk write + one ZLP, same shape as JPEG:
```
BULK ep=0x04 size=1036816  FF 00 ... FF C0 ...     ; header + RGB888 + footer
BULK ep=0x04 size=0                                ; ZLP = end-of-frame  (YES, raw uses a ZLP)
```
Between consecutive frames the worker periodically (NOT every frame) re-reads the
hotplug register:
```
SET  B5 00 32 00 00 00 00 00
GET  -> B5 00 32 09 ...                             ; still connected+stable
```
and once, after the first frame, issues the screen/video re-arm
(`B6 F0 37 01` + `A6 05 01` + poll `B5 11 8D`). No geometry is re-pushed and no
`A6 01/02/04` is repeated as long as `0xF7E9` bit0 stays 1. So the steady-state
loop is simply: `[optional B5 00 32 read] ; BULK(frame) ; BULK(ZLP)` repeated.

**Raw uses a ZLP after every frame, exactly like JPEG.**

================================================================================

## RESULT 4 - orientation: header is LANDSCAPE, matches A6 01 / A6 02

The header encodes **width=720 (0x2D0) in byte5 + high nibble of byte6, and
height=480 (0x1E0) in low nibble of byte6 + byte7** -- i.e. the **resolved
(landscape) dest geometry**, the same hactive/vactive that go out in `A6 01` and
`A6 02`:

```
A6 01: A6 01 | 02 D0 (hactive=720) | 01 E0 (vactive=480) | 11 (fmt RAW) | 00
A6 02: A6 02 | 02 (mode) | 00 | 02 D0 (hactive=720) | 01 E0 (vactive=480)
frame header byte5/6/7 -> width=720, height=480   (SAME landscape orientation)
```

The frame-builder dimensions (r14=width, r13=height) are loaded from the resolved
geometry (`ctx+0x234` hactive -> r14, `ctx+0x238` vactive -> r13), which is what
`SetVideoParam`/the resolver populated and what `A6 01`/`A6 02` programmed. So the
raw frame header is **always in the same orientation as A6 01 hactive/vactive**:
hactive -> header width field, vactive -> header height field.

For the DS339 panel this means: if you drive it as portrait 376x960, then
hactive=376, vactive=960 must be what you pass to `SetVideoParam` / `A6 01` /
`A6 02`, and the frame header must encode width=376, height=960 (=> header
`FF 00 00 00 00 17 83 C0`). If instead you drive it landscape 960x376
(hactive=960, vactive=376), the header is width=960, height=376
(=> `FF 00 00 00 00 3C 01 78`). The header orientation is whatever you set as
hactive/vactive; it is NOT independently rotated by the SDK.

================================================================================

## Summary / what takes the panel out of the logo (raw path)

1. **Corrected raw frame header** (8 bytes), for resolved width W, height H:
   ```
   FF  00  00  00  00  (W>>4)&0xFF  ((H>>8)&0x0F)|((W&0x0F)<<4)  H&0xFF
   ```
   footer = `FF C0 00 00 00 00 00 00`. Pixels = **RGB888 in B,G,R order, 3 B/px**
   (for any mode <= 921600 px, which includes the panel's 376x960), every pixel
   byte 0xFF clamped to 0xFE. (UYVY 2 B/px only for modes > 921600 px; same
   header/footer layout.) Evidence: log line `[75] BULK_WRITE ep=0x04
   size=1036816 first32: FF 00 00 00 00 2D 01 E0 ...` and builder
   `fcn.18001f9f0` @ 0x18001fcb1-0x18001fd1a.

   Our driver's header has **width and height swapped** in bytes 5/6/7 -- this is
   almost certainly why the panel shows black/garbled instead of our content.

2. **The write that leaves the logo** is the A6 bring-up chain ending in
   **`A6 04 01`** (commit), which flips reg `0xF7E9` bit0 0->1 (OSD/logo ->
   host-flushing). There is **no separate OSD-disable / logo-disable / input-
   source register**; the raw control sequence is identical to the JPEG one
   except the `A6 01` fmt byte (`0x11` raw vs `0x22` jpeg). Required order:
   `A6 07 01` -> `A6 05 00` -> screen/F160/F031/flash-gpio init -> `A6 03 03` ->
   `A6 01 .. 0x11` -> `A6 02 ..` -> `A6 04 01`, then per-frame
   `B6 F0 37 01` + `A6 05 01`. Gate: do not bulk-write until `0xF7E9` bit0 == 1.
   Evidence: identical `A6`/`Cx`/`B6` write lists for raw vs jpeg in
   `stub_raw_real.log` vs `stub_geom.log`, differing only at
   `A6 01 02 D0 01 E0 11 00` (raw) vs `... 22 00` (jpeg).

3. Each raw frame is one bulk write **+ a ZLP**, same as JPEG.
