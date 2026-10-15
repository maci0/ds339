# DS339 / MS9132 USB byte-sequence capture (live, via stub libusb0.dll under wine)

Captured by running the **real** `MSDISPLAYSDKWRRAPER.dll` under wine against a
**stub `libusb0.dll`** that logs every `usb_control_msg` / `usb_bulk_write` and
returns canned responses so the SDK walks its full bring-up and per-frame path.
This is observed wire behaviour, not disassembly inference; it confirms and in
two places **corrects** `PROTOCOL.md`.

## Method / artifacts (scratch dir `~/.cache/ds339-cap/`)
- `libusb0_stub.c` + `libusb0.def` -> `libusb0.dll` (stub, undecorated 10 exports).
- `harness.c` -> `harness.exe`: LoadLibrary the SDK, RegisterCallback,
  Start(5, zero-EDID), wait for the attach callback (delivers the handle),
  SetVideoParam(376x960), then SendPicture(handle, gradient BGRA, b=1) x30.
- Run: `WINEPREFIX=~/.cache/ds339-cap/pfx WINEDLLOVERRIDES="libusb0=n" wine harness.exe`,
  SDK + stub + harness all in `C:\ds339cap\`.
- Logs: `stub_d7.log` (chip-id D7, JPEG), `stub_raw00.log` (chip-id 00, raw),
  `stub_geom.log` (D7 + reg0x31=4 forcing a resolvable 720x480 mode so a **real
  JPEG frame** is emitted on EP4).

### Canned stub responses needed to make the SDK proceed (these are the gates)
- `usb_get_busses` -> one bus, one device `idVendor=0x345F idProduct=0x9132 bNumConfigurations=1`.
- `usb_open` -> fake handle; its **low 32 bits are the `handle`** the SDK gives
  you back via the attach callback (`ctx+0x198` truncated to 32-bit).
- chip-id read `B5 FF 00` -> GET returns `B5 FF 00 D7 13 0A 00 00`
  (resp[3]=0xD7 -> JPEG, resp[4]=0x13, resp[5]=0x0A -> chip **0x9132**).
- "command done" polls `0xC454, 0x118D, 0xC515, 0xC555` -> bit0 = 0 (done).
- gate `0xF7E9`/`0xF439`: bit0 must be **0 during init** (else the SDK logs
  "is_osd_flushing at init state" and never powers on) and **1 after the geometry
  commit** (`A6 04 01`) so the per-frame worker proceeds to the bulk write. The
  stub flips it on seeing `A6 04 01`.
- `0xD042`/`0xF242` bit3 = 0 (not mem-freezing).
- **reg `0x32` (hotplug status) = `0x09`**: bit3 (=connected) AND bit0 (the value
  `fcn.18001a760` returns = "stable"). Without bit0 set the worker treats it as
  "HPD lost, remove the display" and the attach callback never fires.

--------------------------------------------------------------------------------

## RESULT 1 - the full ordered control + bulk sequence (from `stub_geom.log`)

`SET` = SET_REPORT `bmRequestType=0x21 bRequest=0x09 wValue=0x0300 wIndex=0`.
Each register READ (`B5 ..`) is a SET_REPORT immediately followed by a
GET_REPORT (`0xA1 0x01 0x0300`, len 8); the value byte is resp[3]. Register
WRITEs (`C5/C6/B6`) are a SET_REPORT + a GET_REPORT write-readback. `A6`
commands are fire-and-forget SET_REPORTs (the geometry ones interleave a status
read). Payloads are the exact 8 bytes on the wire.

```
# ---- open ----
usb_claim_interface(iface=3)

# ---- chip-id (ONE control pair) ----
SET  B5 FF 00 00 00 00 00 00        ; read chip id @0xFF00
GET  -> B5 FF 00 D7 13 0A 00 00     ; D7,13,0A => 0x9132, JPEG-capable

# ---- status reads ----
SET  B5 00 31 00 00 00 00 00        ; reg 0x31 "Video Port" (panel/EDID selector)
SET  B5 00 30 00 00 00 00 00        ; reg 0x30 "SDRAM type"
SET  B5 F7 E9 00 00 00 00 00        ; 0xF7E9 is_osd_flushing (init: bit0 must be 0)
SET  F5 00 1F E0 00 00 00 00        ; flash read 0x1FE0 (serial/name "5A A5 ..")
SET  F5 00 1F E8 00 00 00 00        ; (32 bytes read in 4x F5 chunks)
SET  F5 00 1F F0 00 00 00 00
SET  F5 00 1F F8 00 00 00 00

# ---- init bring-up (fcn.18001a1e0) ----
SET  A6 07 01 02 00 00 00 00        ; set_power_on  (subcmd 07, arg 01) ; note arg2=0x02
SET  B5 C4 54 00 00 00 00 00        ; poll 0xC454 "command done" until bit0==0
SET  A6 05 00 00 00 00 00 00        ; set_video_on(0)
SET  B5 11 8D 00 00 00 00 00        ; poll 0x118D done
SET  B5 F0 37 00 00 00 00 00        ; read 0xF037 (screen reg)  \  set_screen_on(0):
SET  B6 F0 37 00 00 00 00 00        ; write 0xF037 (RMW, B6)     /  read-modify-write
SET  B5 F1 60 00 00 00 00 00        ; read 0xF160               \  (only when reg0x31!=4)
SET  B6 F1 60 00 00 00 00 00        ; write 0xF160 &= 0xDF       /  clear bit5
SET  B6 F0 31 34 00 00 00 00        ; write 0xF031 = 0x34
SET  C5 B0 00 00 00 00 00 00        ; init_flash_gpio (fcn.18001cec0):
SET  C6 B0 00 00 00 00 00 00        ;   C5/C6 register writes ...
SET  C5 A0 00 00 00 00 00 00
SET  C6 A0 04 00 00 00 00 00
SET  C6 C7 D1 00 00 00 00 00
SET  C6 C8 C0 00 00 00 00 00
SET  C6 CA 00 00 00 00 00 00
SET  B5 F0 1F 00 00 00 00 00        ; read 0xF01F
SET  B6 F0 1F 10 00 00 00 00        ; write 0xF01F (APPEND-mode bits)
SET  F5 00 FC 50 00 00 00 00        ; flash read 0xFC50 (custom timing block)
SET  B5 F0 1F 00 00 00 00 00        ; read 0xF01F
SET  B6 F0 1F 00 00 00 00 00        ; write 0xF01F
SET  C5 B0 00 00 00 00 00 00        ; C5/C6 writes  B0=0x3C, B1=0x3C
SET  C6 B0 3C 00 00 00 00 00
SET  C5 B1 00 00 00 00 00 00
SET  C6 B1 3C 00 00 00 00 00

# ---- worker tick: detect display, push geometry, switch to host scanout ----
SET  B5 00 32 00 00 00 00 00        ; reg 0x32 hotplug (bit3 connected, bit0 stable)
SET  B5 F7 E9 00 00 00 00 00        ; re-check flushing
SET  A6 03 03 00 00 00 00 00        ; set_transfer_mode 3
SET  B5 10 26 00 00 00 00 00        ; (status read 0x1026)
SET  A6 01 02 D0 01 E0 22 00        ; INPUT RECT + FORMAT  (see RESULT 2)
SET  B5 11 23 00 00 00 00 00        ; (status read 0x1123)
SET  A6 02 02 00 02 D0 01 E0        ; OUTPUT TIMING        (see RESULT 2)
SET  B5 11 25 00 00 00 00 00        ; (status read 0x1125)
SET  A6 04 01 00 00 00 00 00        ; COMMIT / "input updated"  -> flips 0xF7E9 bit0 -> 1

# ---- per frame ----
BULK ep=0x04 size=51444  FF D8 FF E0 00 10 4A 46 49 46 ...   ; bare JPEG (JFIF)
BULK ep=0x04 size=0                                          ; ZLP = end of frame
SET  B5 00 32 00 00 00 00 00        ; (worker re-reads hotplug each tick)
BULK ep=0x04 size=51444  FF D8 ...                           ; frame 2
BULK ep=0x04 size=0

# ---- "start screen" re-arm, emitted after the first frame ----
SET  B5 F0 37 00 00 00 00 00        ; read 0xF037
SET  B6 F0 37 01 00 00 00 00        ; write 0xF037 = 01  (screen_on)
SET  A6 05 01 00 00 00 00 00        ; set_video_on(1)
SET  B5 11 8D 00 00 00 00 00        ; poll 0x118D done
... (frames continue: BULK 51444 + ZLP, ~once per SendPicture) ...

# ---- shutdown (Stop) ----
usb_release_interface(iface=3); usb_close()
```

So **between Start and the first successful bulk frame**, the device-enabling
control writes are, in order:
`A6 07 01` (power on) -> `A6 05 00` (video off) -> screen/F160/F031/flash-gpio
register init -> `A6 03 03` (transfer mode) -> **`A6 01 .. fmt`** (input rect +
format) -> **`A6 02 .. timing`** (output timing) -> **`A6 04 01`** (commit, this
is what flips `0xF7E9` bit0 to 1 and lets the worker send). The per-frame
`A6 05 01` + `F037=01` (screen/video on) is a re-arm that lands **after** the
first frame, not before it.

--------------------------------------------------------------------------------

## RESULT 2 - A6 01 / A6 02 geometry encoding (8-byte HID form, hid9=0)

From `stub_geom.log` (reg0x31=4 -> resolver forces mode 2 / 720x480 =
0x02D0 x 0x01E0), decoded against the builders `fcn.18001eab0`/`fcn.18001eda0`
and their call sites in `fcn.18001a840` (apply_input_rect). The args are:
`eab0(ctx, hactive=ctx+0x234, vactive=ctx+0x238, fmt)`,
`eda0(ctx, mode=ctx+0x230, hactive=ctx+0x234, vactive=ctx+0x238)`. **All
16-bit timing fields are big-endian (hi byte first).**

```
A6 01: wire [A6 01 02 D0 01 E0 22 00]
        A6 01  | 02 D0    | 01 E0    | 22  | 00
               | hactive  | vactive  | fmt | pad
               | =0x02D0  | =0x01E0  |     |
               | =720     | =480     | 0x22 JPEG / 0x11 raw (RESULT 4)
   (NO mode byte in A6 01; bytes [2,3]=hactive, [4,5]=vactive, [6]=fmt.)

A6 02: wire [A6 02 02 00 02 D0 01 E0]
        A6 02  | 02   | 00 | 02 D0    | 01 E0
               | mode |    | hactive  | vactive
               |=0x02 |    | =0x02D0  | =0x01E0
               |      |    | =720     | =480
   ([2]=mode (ctx+0x230), [3]=00, [4,5]=hactive, [6,7]=vactive.)
```

(With a zero EDID and the panel's 376x960 -- which is in NO timing table and is
not the reg0x31==4 forced mode -- the resolver leaves mode/hactive/vactive = 0,
so you get the degenerate `A6 01 00 00 00 00 22 00` / `A6 02 42 00 00 00 00 00`
and an empty frame. On real hardware the SDK is handed a real EDID and the
panel's native timing comes from the EDID-derived table, populating these.)

--------------------------------------------------------------------------------

## RESULT 3 - per-frame bulk format (confirmed on the wire)

JPEG path, `stub_geom.log`:
```
BULK_WRITE ep=0x04 size=51444  FF D8 FF E0 00 10 4A 46 49 46 00 01 ...   (JFIF/JPEG)
BULK_WRITE ep=0x04 size=0                                                (ZLP)
```
- The payload is the **bare JPEG** (`FF D8 ... FF D9`), no 8-byte header, no
  length prefix, no `FF C0` terminator.
- `size=51444` is a multiple of 4 (zero-padded to %4 as PROTOCOL.md §4b says).
- Each frame = one big `usb_bulk_write` to **EP 0x04** + a **zero-length packet**.
- 30 SendPicture calls -> 30 (`JPEG`, `ZLP`) pairs.

--------------------------------------------------------------------------------

## RESULT 4 - JPEG vs raw run, and a CORRECTION to PROTOCOL.md

Two full runs, varying only the chip-id byte resp[3]:

| run         | resp[3] | jpeg flag (ctx+0x5A1) | `A6 01` fmt byte | bulk payload |
|-------------|---------|-----------------------|------------------|--------------|
| `stub_d7`   | 0xD7    | 1 (set)               | **0x22**         | bare JPEG (`FF D8 ...`) |
| `stub_raw00`| 0x00    | 0 (clear)             | **0x11**         | `FF 00 ...pixels... FF C0` (legacy framing) |

**CORRECTION to PROTOCOL.md - the fmt byte mapping is inverted there.** The
selector in `fcn.18001a840` is:
```
area = hactive * vactive
fmt = (area > 0xE1000)            ? 0x22
    : (ctx+0x594 fallback != 0)   ? 0x22
    : (ctx+0x5A1 jpeg_flag == 0)  ? 0x11      <-- jpeg_flag CLEAR -> 0x11
    :                               0x22      <-- jpeg_flag SET   -> 0x22
```
i.e. **fmt 0x22 = JPEG path, fmt 0x11 = raw/RGB path** (PROTOCOL.md §7.7 has them
swapped). The live captures match this exactly: the D7/JPEG run sends `A6 01 ..
0x22` and a bare JPEG; the 00/raw run sends `A6 01 .. 0x11` and the
`FF 00 ... FF C0` framed buffer.

Everything else in PROTOCOL.md (§1 B5/C5 framing, §4b bare-JPEG + ZLP, the
`A6 07/05/03/01/02/04` command family and ordering, the `0xF7E9` gate) is
confirmed verbatim by the capture.

--------------------------------------------------------------------------------

## RESULT 5 - concrete pyusb init + per-frame sequence to replicate

VID:PID `345F:9132`. CTRL_OUT=0x21 (SET_REPORT 0x09), CTRL_IN=0xA1 (GET_REPORT
0x01), wValue=0x0300, wIndex=0, len 8, timeout 1000 ms. BULK_EP=0x04, 3000 ms.

```python
def setrep(dev, payload8):  dev.ctrl_transfer(0x21, 0x09, 0x0300, 0, payload8)
def getrep(dev):            return dev.ctrl_transfer(0xA1, 0x01, 0x0300, 0, 8)

# open
dev.set_configuration(); usb.util.claim_interface(dev, 3)

# chip id (one pair)
setrep(dev, [0xB5,0xFF,0x00,0,0,0,0,0]); r = getrep(dev)
assert r[4]==0x13 and r[5]==0x0A          # 0x9132
jpeg = (r[3]==0xD7)                         # JPEG only if resp[3]==0xD7

# init bring-up
setrep(dev,[0xA6,0x07,0x01,0x02,0,0,0,0])   # power on   ; poll 0xC454 bit0->0
setrep(dev,[0xA6,0x05,0x00,0,0,0,0,0])      # video off  ; poll 0x118D bit0->0
# (screen_on(0): RMW 0xF037 via B5 read + B6 write; if reg0x31!=4 also
#  clear 0xF160 bit5 and write 0xF031=0x34; init_flash_gpio C5/C6 block;
#  these mostly mirror the device's power state and can be replayed verbatim
#  from the log if a panel needs them.)

# geometry push (use the panel's wire WxH; all 16-bit fields are BIG-ENDIAN)
mode = 0x02                                  # resolver mode byte (ctx+0x230)
fmt  = 0x22 if jpeg else 0x11               # 0x22 = JPEG, 0x11 = raw
hi_h, lo_h = (W>>8)&0xFF, W&0xFF            # hactive
hi_v, lo_v = (H>>8)&0xFF, H&0xFF            # vactive
setrep(dev,[0xA6,0x03,0x03,0,0,0,0,0])                      # transfer mode 3
setrep(dev,[0xA6,0x01, hi_h, lo_h, hi_v, lo_v, fmt, 0])     # input rect+fmt: hactive,vactive,fmt
setrep(dev,[0xA6,0x02, mode, 0x00, hi_h, lo_h, hi_v, lo_v]) # output timing: mode,00,hactive,vactive
setrep(dev,[0xA6,0x04,0x01,0,0,0,0,0])                      # commit -> 0xF7E9 bit0 -> 1

# (optional) wait until reg 0xF7E9 bit0 == 1 before sending
# setrep(dev,[0xB5,0xF7,0xE9,0,0,0,0,0]); while not (getrep(dev)[3] & 1): ...

# per frame
jpeg_bytes += b'\x00' * ((-len(jpeg_bytes)) & 3)            # pad to %4
dev.write(0x04, jpeg_bytes, timeout=3000)                  # one bulk write
dev.write(0x04, b'',        timeout=3000)                  # ZLP = end of frame
# after the first frame the SDK also re-arms: F037=01 + A6 05 01 (video on).
```

Field order (verified from the builders' call sites in `fcn.18001a840`):
`A6 01` = `[A6, 01, hactive_hi, hactive_lo, vactive_hi, vactive_lo, fmt, 00]`
(no mode byte). `A6 02` = `[A6, 02, mode, 00, hactive_hi, hactive_lo,
vactive_hi, vactive_lo]`. When in doubt, replicate the exact bytes from
`stub_geom.log` for the target resolution.

**JPEG encoder params (from PROTOCOL.md §5, unchanged): BGRA in, TJSAMP_422,
quality 95, accurate DCT, height padded up to %8, output padded to %4.**

--------------------------------------------------------------------------------

## Why your reimplementation stayed on the logo
The worker hard-gates every bulk write on **`0xF7E9` bit0 == 1**, which is set
only after the `A6 03 03 / A6 01 / A6 02 / A6 04 01` geometry+commit sequence
(driven by a resolved mode from SetVideoParam). Draining EP4 alone never leaves
the logo; you must run the `A6` bring-up + commit first so the panel enters
host-JPEG scanout, then send `<JPEG> + ZLP` to EP 0x04.
