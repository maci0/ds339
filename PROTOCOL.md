# Jonsbo DS339 (MacroSilicon MS9132) USB wire protocol

Reverse-engineered from `MSDISPLAYSDKWRRAPER.dll` (PE32+, x86-64, libusb-0.1 +
statically-linked libjpeg-turbo 3.0.5). Device USB VID:PID `345f:9132`.

All addresses below are file/virtual addresses in that DLL. Evidence is quoted
from rizin disassembly / Ghidra (`pdg`) output.

Key correction vs. the assumed ms912x scheme: **the DS339 SDK does NOT use the
`0xA6` register-write / UYVY framing on this firmware.** It uses a different
HID opcode family (`0xB5` read, `0xC5` write) and, for the picture path, sends a
**bare JPEG** over the bulk endpoint with no `0xFF 0x00` header and no `0xFF 0xC0`
terminator. The `0xFF/0x00 ... 0xFF/0xC0` framing only exists in the *fallback*
UYVY / RGB888 code paths, which are not used when the chip reports JPEG support.

--------------------------------------------------------------------------------

## 0. Device model

- Interface 0: HID. Control/register channel via USB **control transfers**
  (HID class SET_REPORT / GET_REPORT on the default control pipe). The 4-byte
  interrupt-IN EP 0x81 is the ack channel but the SDK does register I/O purely
  over the control pipe.
- Interface 3: vendor class 0xFF, **BULK OUT endpoint 0x04**, 512-byte packets.
  This carries the picture payload (JPEG).
- `usb_claim_interface(handle, 3)` is the only interface the SDK claims
  (`fcn.18001a1e0 @ 0x18001a22d`; error string "libusb_claim_interface3 Failed %d.").

--------------------------------------------------------------------------------

## 1. Register read / write primitives (control_msg) — DELIVERABLE #1

Every register primitive issues HID class requests on the control pipe. There is
a whole opcode family; the first payload byte selects the operation:

| helper fcn   | opcode | operation                         |
|--------------|--------|-----------------------------------|
| 18001cc30    | 0xB5   | read N bytes from a 16-bit addr   |
| 18001d940    | 0xB5   | read 1 byte from a 16-bit addr    |
| 18001d0a0    | 0xC5   | write 1 byte to addr (xdata/reg)  |
| 18001d300    | 0xC6   | write burst                       |
| 18001d490    | 0xE5   | EEPROM read                       |
| 18001d730    | 0xE6   | EEPROM write                      |
| 18001de50/dfe0 | 0xB6 | xdata read variants               |
| 18001dba0    | 0xF5   | flash read                        |
| 18001e1f0    | 0xF6   | flash write                       |

All of them use the **same control_msg framing**:

```
SET_REPORT (send command):  bmRequestType=0x21, bRequest=0x09, wValue=0x0300,
                            wIndex=0x0000, length=8 (or 9), timeout=1000 ms
GET_REPORT (read result):   bmRequestType=0xA1, bRequest=0x01, wValue=0x0300,
                            wIndex=0x0000, length=1 .. 8, timeout=1000 ms
```

Evidence — read primitive `fcn.18001cc30`:
```
0x18001ccb1  mov  byte [rsp+rcx+0x48], 0xb5      ; payload[0] = 0xB5
0x18001cd07  mov  edx, 0x21                      ; bmRequestType = 0x21
0x18001cd29  lea  r8d, [rdx-0x18]                ; bRequest = 0x21-0x18 = 0x09 (SET_REPORT)
0x18001cd1a  add  r9d, 0x300                     ; wValue = 0x0300
0x18001cd2d  call usb_control_msg                ; <-- send B5 packet
...
0x18001cd85  mov  edx, 0xa1                      ; bmRequestType = 0xA1
0x18001cd8f  mov  r8d, 1                          ; bRequest = 0x01 (GET_REPORT)
0x18001cd9e  add  r9d, 0x300                     ; wValue = 0x0300
0x18001cdad  call usb_control_msg                ; <-- read result
```

### 1a. READ packet layout (opcode 0xB5)

8-byte form (used by the DS339 — see §2, hid9 flag = 0):
```
[ 0xB5, addr_hi, addr_lo, 0x00, 0x00, 0x00, 0x00, 0x00 ]
```
- `addr_hi = (addr >> 8) & 0xFF`, `addr_lo = addr & 0xFF`.
- Then GET_REPORT (0xA1, 0x01, 0x0300) returns 8 bytes; the register value is
  byte **[3]** (the response echoes `[B5, addr_hi, addr_lo, VALUE, ...]`).
- `fcn.18001cc30` reads N consecutive bytes by looping the address; each
  iteration returns one byte (this is how the 3-byte chip-id at 0xFF00 is read).

9-byte form ("@ 9 bytes" chip variant, hid9 flag at struct+0x5A2 = 1):
a leading HID **Report-ID byte** is prepended, shifting everything by one:
```
[ report_id, 0xB5, addr_hi, addr_lo, 0,0,0,0,0 ]   (9 bytes)
```
and the returned value is at byte **[4]**. The SDK auto-detects which form the
chip wants (see §2; for the 0x9132 DS339 it is the 8-byte form).

### 1b. WRITE packet layout (opcode 0xC5, `fcn.18001d0a0`)
```
0x18001d0f0  mov byte [rsp+rax+0x40], 0xc5       ; payload[0] = 0xC5
0x18001d0fe  mov byte [rsp+rax+0x40], dl         ; payload[1] = addr low byte
0x18001d196  lea edx, [r13+0x20]                 ; bmRequestType = 0x21
0x18001d19e  lea r8d, [r13+8]                    ; bRequest = 0x09 (SET_REPORT)
0x18001d1ab  add r9d, 0x300                      ; wValue = 0x0300
```
Packet (8 bytes, +1 report-id in 9-byte mode):
```
[ 0xC5, addr, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
```
A second control_msg (GET_REPORT) immediately follows as a write-readback.

> Note: the `0xA6 [addr_lo] d0..d5` six-data-byte register write from the ms912x
> HDMI driver is **not** what this firmware uses. The DS339 firmware register
> write is the single-byte `0xC5 addr` form above.

--------------------------------------------------------------------------------

## 2. MSDisplayStart / init sequence — DELIVERABLE #2

`Wrraper_MSDisplayStart(loglevel, edid)` @ 0x1800146e0 sets up logging, copies
the caller-supplied EDID buffer into the device context, and spawns a worker
thread. Per-device bring-up happens in `fcn.18001a1e0` (the device-init/poll
routine). Concrete touches, in order:

1. `usb_claim_interface(handle, 3)` (vendor/bulk interface). On failure logs
   "libusb_claim_interface3 Failed %d." and forces state 4.
2. **Chip-ID detection** — `fcn.18001f660`:
   - Read 3 bytes from address **0xFF00** with the 0xB5 read primitive
     (`fcn.18001cc30(ctx, 0xFF00, 3, buf)`), then if that fails try **0xF000**,
     then retry 0xFF00 with the hid9 (9-byte) report form.
   - Decode `chip_id`:
     - `buf[1]==0x13 && buf[2]==0x3A` -> 0x9133, sets **jpeg flag** (+0x5A1)=1
     - `buf[1]==0x13 && buf[2]==0x0A` -> **0x9132** (DS339); jpeg flag=1 iff `buf[0]==0xD7`
     - `buf[1]==0x16 && buf[2]==0x0A` -> 0x912C / 0x912A / 0x9120
     - `buf[0]==0xC5 && buf[1]==0x12` -> 0x5120, jpeg flag=1
   - Stores chip_id at ctx+0x28, jpeg flag at ctx+0x5A1, hid9 ("@9 bytes")
     flag at ctx+0x5A2. Logs `chip_id %04x, hid9 %d, jpeg %d`.
   - For the DS339 the 0xFF00 / "@ 8 bytes" read succeeds first, so **hid9=0
     (8-byte packets) and jpeg=1**.
3. Read status registers with the single-byte 0xB5 read (`fcn.18001d940`):
   - reg **0x31** -> stored ctx+0x1A0 (panel/edid-mode selector; value 4 forces
     a 720x480 mode in the timing resolver, see §3)
   - reg **0x30** -> stored ctx+0x1A4
   - reg **0xF7E9** (0x9132) / **0xF439** (others): poll bit0 = "busy/flushing".
4. Read a 32-byte block from address **0x1FE0** (`fcn.18001dba0`, flash-read
   0xF5). If it begins `5A A5 xx` (`'Z',0xA5,...`) it is a name/SN descriptor;
   the printable tail is copied to ctx+0x30 as the device serial.
5. `fcn.18001f340` finishes timing/EDID setup.

EDID supplied by the caller is stored in the context and used by the timing
resolver (§3) to build the per-device mode table at ctx+0x414.

--------------------------------------------------------------------------------

## 3. MSDisplaySetVideoParam — DELIVERABLE #3

`Wrraper_MSDisplaySetVideoParam(handle, MSDisplayTiming*)` @ 0x1800149c0 reads
only the first two uint32 fields of the struct (`struct[0]`, `struct[4]`) and
calls the resolver `fcn.18001c380(ctx, w, h, ...)`. The resolver returns
`hactive` (-> ctx+0x234), `vactive` (-> ctx+0x238) and a **mode byte**
(-> ctx+0x230), then marks the device "video set" (ctx+0x23C=1). These resolved
hactive/vactive are later compared against the worker's frame geometry before
each bulk send ("worker's resolution is inconsistant" guard).

Resolver `fcn.18001c380` logic:
- If reg 0x31 (ctx+0x1A0) == 4: **force 0x2D0 x 0x1E0 (720x480), mode 2**, return.
- Else search two timing tables for a record whose width/height match and whose
  vfreq rounds to 60 Hz (`(vfreq+0x32)/100 == 0x3C`):
  - dynamic, EDID-derived table at ctx+0x414 (stride 0x16, count ctx+0x408)
  - static built-in table at **0x180099678** (15 records, stride 0x16 = 22 bytes)
- The matched record yields the mode byte (base 0x180099670).

Static timing table (each record 22 bytes; mode/aux bytes + 16-bit timing
fields). Parsed 16-bit fields per record (`0x180099670 + i*22`):

```
rec  fields (hword[0..10], little-endian)
 0   0781 0898 0465 0780 0438 3a02 1770 00c0 0029 002c 0005
 1   0578 08c0 0441 0690 041a 3921 176b 01c8 0024 00b0 0006
 2   056b 0770 03a6 05a0 0384 299a 1765 0180 001f 0098 0006
 3   0764 0700 031b 0550 0300 2166 1772 0170 0018 0070 0006
 4   0760 0698 042a 0500 0400 2a30 1772 0168 0029 0070 0003
 5   075b 0708 03e8 0500 03c0 2a30 1770 01a8 0027 0070 0003
 6   0557 0690 033f 0500 0320 209e 175d 0148 001c 0080 0006
 7   0554 0680 031e 0500 0300 1f0e 1763 0140 001b 0080 0007
 8   074f 0672 02ee 0500 02d0 1d01 1770 0104 0019 0028 0005
 9   054e 0670 026e 0500 0258 1806 1770 0138 0015 0080 0003
10   054c 05f0 037f 0480 0360 1fe2 1770 0130 001e 0078 0003
11   0147 0540 0326 0400 0300 1964 1770 0128 0023 0088 0006
12   0742 0420 0274 0320 0258 0fa0 1790 00d8 001b 0080 0004
13   0140 0320 020d 0280 01e0 09d5 176a 0090 0023 0060 0002
14   0111 0360 0271 02d0 0240 0a8c 1388 0084 002c 0040 0005
```
These are standard HDMI-ish landscape timings (1280x1024, 1920x1080, 1024x768,
etc.; the `0x1770 = 6000` field is vfreq*100 = 60 Hz). **376x960 is not in this
table**: the DS339 panel is fixed and is driven through the reg-0x31==4 forced
mode (720x480) or the EDID-derived table at ctx+0x414. The panel's physical
376x960 is reached by sending the JPEG at the panel's wire geometry; the SDK
does not need a VIC number for a JPEG-capable panel.

--------------------------------------------------------------------------------

## 4. MSDisplaySendPicture — JPEG framing — DELIVERABLE #4 (MOST IMPORTANT)

`Wrraper_MSDisplaySendPicture(handle, MSDisplayPicture* pic, bool b)` @ 0x180014b40.
`MSDisplayPicture { int Width @0; int Height @4; void* data @8 }`.

```
0x180014b57  mov eax, [rdx+4]      ; Height
0x180014b5a  mov r9d,[rdx]         ; Width
0x180014b5d  mov [var_10h], r8b    ; bool b
0x180014b62  mov r8,[rdx+8]        ; data ptr
0x180014b73  call fcn.180018360    ; -> queues frame, double-buffered
```
Flow: `fcn.180018360` (locates the device, grabs a free double-buffer slot) ->
`fcn.18001f9f0` (the **frame builder**, writes the wire bytes into the slot
buffer and the byte-count into the slot length field) -> a worker thread later
bulk-writes the slot to EP 0x04 via `fcn.18001c660`.

### 4a. Which encoding is used — what `bool b` does
`fcn.18001f9f0` chooses the encoding from two flags:

```
uVar7 = ctx[0x5A1];                 // chip JPEG-capable flag (from chip-id detect)
if (uVar7 != 0  &&  (char)b != 0)   // JPEG path
0x18001fb10  cmp byte [arg_48h], 0  ; arg_48h = (jpeg_capable && b)
0x18001fb18  je  <non-jpeg>
```
- **`b == true` AND chip JPEG-capable (DS339): JPEG path** (`fcn.18001ffc0`).
- `b == false` (or non-JPEG chip): falls through to the legacy raw encoders:
  - `Height*Width*pixel > 0xE1000` or fallback flag -> **UYVY** (2 bytes/px),
  - else -> **RGB888** (3 bytes/px).
  Those legacy paths *do* build the `0xFF 0x00 ... 0xFF 0xC0` framing (see §4d).

So `bool b` is effectively **"is this buffer a JPEG"** (compress / send-as-JPEG).
The C# app always passes a JPEG buffer with `b = true`.

### 4b. JPEG wire format — what actually goes on EP 0x04
In the JPEG branch (`fcn.18001f9f0` @ 0x18001fb1a -> `fcn.18001ffc0`):

1. The JPEG is encoded (or, if `data` is already JPEG, passed through — see §5)
   directly into the slot buffer.
2. The byte count is rounded **up to a multiple of 4** and the pad bytes are
   zero-filled:
   ```
   0x18002015d  lea ecx, [rbx+3]
   0x180020160  and ecx, 0xfffffc          ; size = (jpeg_len + 3) & ~3
   0x180020170  mov byte [rsi+rbx], 0       ; zero-pad the tail
   ```
3. `*arg_40h = padded_size` (logged as `EncodeJpeg size %d`). That padded size is
   stored into the slot's length field (ctx-slot+0x1BC).

**There is NO 8-byte header and NO `0xFF 0xC0` terminator in JPEG mode.** The
wire payload is exactly: `<JPEG bytes> <0..3 zero pad to %4>`. No length prefix
is prepended either; the JPEG's own `FF D8 ... FF D9` markers delimit the frame
and the controller's JPEG decoder consumes it.

The height passed to the encoder is rounded up to a multiple of 8:
```
0x18001fb2a  lea r9d, [r13+7]
0x18001fb36  and r9d, 0xfff8              ; jpeg_height = (Height + 7) & ~7
```

### 4c. Bulk transfer — `fcn.18001c660` (the per-frame sender)
```
0x18001c97a  mov dword [var_48h], 0xbb8   ; timeout = 3000 ms
0x18001c982  mov edx, 4                   ; endpoint = 0x04 (BULK OUT)
0x18001c977  mov r8, rdi                  ; data   = slot+0x1C0
0x18001c974  mov r9d, r15d                ; length = slot+0x1BC (padded JPEG size)
0x18001c987  call usb_bulk_write
...
0x18001c9f3  call usb_bulk_write          ; second call: endpoint 4, length 0 -> ZLP
```
So each frame is: **one `usb_bulk_write` of the whole padded JPEG to EP 0x04**,
followed by a **zero-length packet** (ZLP) on EP 0x04 to mark end-of-frame.
(libusb auto-splits the big write into 512-byte USB packets; the ZLP is the
explicit terminator because the JPEG size is a multiple of 4, often a multiple
of 512, so a ZLP is needed to flush.) Timeout 3000 ms; on `0xFFFFFF8C` it logs
"msdisplay_bulk_transfer timeout happen".

Before the first frame the worker may emit a "start screen" handshake
(`fcn.18001f530` / `fcn.18001f090`, logged "start screen for data size %d") and,
if the controller is mid OSD/freeze, it manipulates regs 0xF7E9/0xD042/0xF242
(0x9132 vs others) before sending.

### 4d. Legacy (non-JPEG) framing, for reference only
When `b==false` (raw UYVY/RGB), `fcn.18001f9f0` builds an 8-byte header + pixels
+ 8-byte footer in the slot buffer:
```
hdr[0]=0xFF
hdr[1]=0x02 if a flag(ctx+0x5A1) else 0x00       ; encoding selector bit
hdr[2..3]=0x0000
hdr[4]=0x00
hdr[5]=(Height>>4)                                ; (note: width/height roles
hdr[6]=((Width>>8)&0xF) | ((Height&0xFF)<<4)        depend on rotation)
hdr[7]=(Width&0xFF)
... pixels (UYVY: 2 B/px, or RGB888: 3 B/px, with any 0xFF byte clamped to 0xFE)
footer[0]=0xFF
footer[1]=0xC0 | (0x02 if flag)
footer[2..7]=0
```
This matches the ms912x `FF 00 ... FF C0` scheme and is the path the existing
`ds339.py` emulates. It is the wrong path for the DS339 (which is JPEG-capable);
use §4b.

--------------------------------------------------------------------------------

## 5. JPEG / TurboJPEG parameters — DELIVERABLE #5

`fcn.18001ffc0` is the TurboJPEG-3 compressor wrapper. Calls and parameters
(strings confirm the TJPARAM names; all are UTF-16LE in .rdata):

```
tj3Init(2)                                  ; "creating TurboJPEG instance"
tj3Set(h, TJPARAM_SUBSAMP   = 4, 1)         ; subsamp = TJSAMP_422
tj3Set(h, TJPARAM_QUALITY   = 3, 0x5F=95)   ; quality = 95
tj3Set(h, TJPARAM_FASTDCT   =10, 0)         ; 0 => accurate (ISLOW) DCT
tj3Set(h, TJPARAM_RESTARTBLOCKS = 18, 1)    ; 1 restart marker per MCU row block
tj3Compress8(h, srcBuf, width, pitch=0, height, pixelFormat=8, &jpegBuf, &jpegSize)
```
Evidence (`tj3Compress8` call @ 0x180020100):
```
0x180020104 mov r8d, ebp            ; width
0x180020117 mov dword[var_60h], 8   ; pixelFormat = 8  (TJPF_BGRA)
0x18002011f mov dword[var_68h], r15d; height
0x180020124 call fcn.180024ce0      ; tj3Compress8
0x18002012d str "tj3Compress8 ret = %d"
```
- **pixelFormat = 8 = TJPF_BGRA** (4 bytes/pixel, B,G,R,A order — matches the
  earlier `width*4` source stride used in `fcn.18001f9f0`).
- pitch = 0 (libjpeg computes width*4).
- **subsampling = TJSAMP_422 (value 1), quality = 95, accurate DCT, 1 restart
  block.** Output is the raw JFIF/JPEG byte stream, then zero-padded to %4 (§4b).

(If the C# caller passes an already-encoded JPEG and the encode is skipped, the
same padding/bulk path applies; pixelFormat/subsamp only matter when the DLL
encodes RGBA/BGRA pixels itself.)

--------------------------------------------------------------------------------

## 6. Reference pseudocode: open -> init -> set mode -> send one JPEG frame
Concrete bytes a pyusb implementation can replicate against the device.

```python
VID, PID = 0x345F, 0x9132
CTRL_OUT = 0x21      # OUT | CLASS | INTERFACE  (SET_REPORT)
CTRL_IN  = 0xA1      # IN  | CLASS | INTERFACE  (GET_REPORT)
SET_REPORT, GET_REPORT = 0x09, 0x01
WVALUE   = 0x0300    # report type=Output(0x03), report id=0
BULK_EP  = 0x04
# DS339 (chip 0x9132) detected as "@ 8 bytes" -> 8-byte HID packets.

def reg_read(dev, addr):                      # opcode 0xB5
    pkt = bytes([0xB5, (addr>>8)&0xFF, addr&0xFF, 0,0,0,0,0])
    dev.ctrl_transfer(CTRL_OUT, SET_REPORT, WVALUE, 0, pkt)        # send
    resp = dev.ctrl_transfer(CTRL_IN, GET_REPORT, WVALUE, 0, 8)   # read back
    return resp[3]                            # value byte (index 3; index 4 if 9-byte chip)

def reg_write(dev, addr_byte, ):              # opcode 0xC5 (single addr byte)
    pkt = bytes([0xC5, addr_byte & 0xFF, 0,0,0,0,0,0])
    dev.ctrl_transfer(CTRL_OUT, SET_REPORT, WVALUE, 0, pkt)
    dev.ctrl_transfer(CTRL_IN, GET_REPORT, WVALUE, 0, 8)          # write-readback

def init(dev):
    dev.set_configuration()
    usb.util.claim_interface(dev, 3)          # vendor/bulk interface
    cid = bytes(reg_read(dev, 0xFF00+i) for i in range(3))   # chip-id @ 0xFF00
    assert cid[1] == 0x13 and cid[2] == 0x0A  # -> 0x9132, JPEG-capable
    reg_read(dev, 0x31); reg_read(dev, 0x30)  # mode/status
    # (optional) poll reg 0xF7E9 bit0 until idle

def send_jpeg(dev, jpeg_bytes):
    buf = jpeg_bytes
    buf += b"\x00" * ((-len(buf)) & 3)        # zero-pad to multiple of 4
    dev.write(BULK_EP, buf, timeout=3000)     # one bulk write, EP 0x04
    dev.write(BULK_EP, b"", timeout=3000)     # zero-length packet = end-of-frame
    # NO 0xFF00 header, NO 0xFFC0 footer in JPEG mode.

# Producing the JPEG (matching the SDK exactly):
#   pixels: BGRA, width x height (height padded up to multiple of 8)
#   tjpeg: subsamp=TJSAMP_422, quality=95, accurate DCT, restartblocks=1
#   e.g. PIL: img.convert("RGB").save(buf, "JPEG", quality=95, subsampling="4:2:2")
#   (PIL emits RGB JFIF; the controller decodes standard JPEG, so RGB is fine.)
```

For the 376x960 portrait panel: render/rotate the image to the panel's wire
geometry, JPEG-encode it (quality 95, 4:2:2), pad to %4, and bulk-write to EP
0x04 followed by a ZLP. `MSDisplaySetVideoParam` is only needed to register the
nominal timing/mode in the SDK's bookkeeping; the JPEG itself carries the image
dimensions, so the panel does not require a VIC number to display a frame.

--------------------------------------------------------------------------------

## Summary of the two headline answers

**#1 control_msg:** READ = SET_REPORT(`0x21,0x09,0x0300,0`) of
`[0xB5,addr_hi,addr_lo,0,0,0,0,0]` then GET_REPORT(`0xA1,0x01,0x0300,0`, len 8),
value at byte[3]. WRITE = SET_REPORT of `[0xC5,addr,0,0,0,0,0,0]` + readback.
9-byte chip variant prepends a report-id byte (value then at byte[4]). The
`0xA6`/6-data-byte ms912x write is NOT used here.

**#4 SendPicture/JPEG:** endpoint **0x04** BULK OUT; payload is the **bare JPEG**
zero-padded to a multiple of 4 bytes; **no header, no length prefix, no 0xFF/0xC0
terminator**; the frame is one `usb_bulk_write` followed by a **zero-length
packet**; timeout 3000 ms. `bool b` selects JPEG (true, when the chip's JPEG flag
is set) vs. legacy raw UYVY/RGB framing (false).

--------------------------------------------------------------------------------

## 7. Pre-frame handshake & init register writes

This section corrects/extends the earlier guesses. It is the priority finding:
the bulk timeout is almost certainly because the device was never put into the
"flushing" (host-display) state, which the worker *checks* before every bulk
write and *refuses to send* if it is not set.

(Decompiled with `rizin`/`pdf`; `pdg` crashes on this binary, `pdf`/`pd` used.)

### 7.0 The real control protocol: a `0xA6 <subcmd>` HID command family

The register read/write primitives in §1 (`0xB5`/`0xC5`/`0xB6`/`0xF5`...) are
correct, but there is a **second, higher-level command family** carried on the
*same* HID control pipe that §1-§6 missed. Every "set state" operation is a
`SET_REPORT` of `[0xA6, subcmd, ...args]` (NO GET_REPORT readback for the
fire-and-forget ones; the geometry ones do a readback). Same framing as §1:

```
bmRequestType=0x21, bRequest=0x09, wValue=0x0300, wIndex=0, timeout=1000 ms
(9-byte HID variant prepends a report-id byte, shifting subcmd to [2]; DS339=8-byte)
```

Command table (sub-byte = payload[1]):

| helper fcn  | payload (8-byte form)                         | meaning / log string        |
|-------------|-----------------------------------------------|-----------------------------|
| 18001f340   | `A6 07 01 00 ...`                             | **set_power_on** (then poll reg `0xC454` bit0 = done) |
| 18001eab0   | `A6 01 modeHi modeLo vactHi vactLo fmt ...`   | **set input rect / format** (fmt=`0x11` JPEG, `0x22` raw) |
| 18001eda0   | `A6 02 modeLo 00 hactHi hactLo vactHi vactLo` | **set output timing** (mode/hactive/vactive) |
| 18001e800   | `A6 03 03 00 ...`                             | **set_transfer_mode 3**     |
| 18001e640   | `A6 04 v 00 ...`                              | **set/clear "input updated" flag** (v=1 arm, v=0 clear) |
| 18001f090   | `A6 05 on 00 ...`                            | **set_video on/off** (then poll done reg, see 7.2) |
| 18001f530   | (no A6; B5 read + B6 write, see 7.3)          | **screen on/off** (panel backlight/output bit) |

`0xA6 05/07` etc. are *commands*, not the ms912x "A6 addr d0..d5" register write.
Do not confuse them with §1's register ops.

### 7.1 chip-id read is ONE transfer (corrects §1a / §0)

`fcn.18001f660` calls `fcn.18001cc30(ctx, 0xFF00, count=3, buf)`. `fcn.18001cc30`
reads in **chunks of up to 4 bytes per control-transfer pair**, NOT one byte per
address. For count=3 there is exactly **one** SET_REPORT+GET_REPORT pair:

```
SET_REPORT [0xB5, 0xFF, 0x00, 0,0,0,0,0]            ; addr 0xFF00, 8-byte packet
GET_REPORT (0xA1,0x01,0x0300, len 8) -> resp[8]
```
The 3 id bytes are copied from `resp[3], resp[4], resp[5]`:
```
0x18001cdda  lea rdx, [rsp + r15 + 0x43]   ; r15=8 -> src = respbuf+0x4B = resp[3]
0x18001cdf3  call memcpy                    ; copy min(remaining,4) bytes
0x18001f6a6  movzx r15d, byte [rsp+0x31]    ; buf[1]  (=resp[4]) -> must be 0x13
0x18001f6b3  movzx r14d, byte [rsp+0x32]    ; buf[2]  (=resp[5]) -> must be 0x0A
0x18001f6bc  mov   ebx,  dword [rsp+0x30]   ; buf[0]  (=resp[3])
```
So **the whole id is in one GET_REPORT response at bytes [3],[4],[5]**. Our
3x single-byte reads of 0xFF00/0xFF01/0xFF02 returning 00 00 00 were the wrong
transfer shape AND read the wrong response index. Read once at 0xFF00, len 3,
and take resp[3..5].

Decode (`fcn.18001f660`): `buf[1]==0x13 && buf[2]==0x0A` -> chip **0x9132**
(DS339). The **JPEG flag (ctx+0x5A1) is set ONLY if buf[0]==0xD7**
(`0x18001f701 cmp bl,0xD7`). If the expected id is `00 13 0A` then buf[0]=0x00,
so **jpeg flag = 0** and the SDK would take the raw UYVY/RGB path, not JPEG.
Worth re-checking the real buf[0] on hardware: only buf[0]==0xD7 enables JPEG.

### 7.2 set_video on/off `fcn.18001f090` (the "start screen" half)

Sends `[0xA6, 0x05, on]` (`on`=1 for screen-on at frame time, 0 at init), then
**polls a "command done" register** until bit0 clears, per chip:
```
0x18001f22a 0x9132 -> poll reg 0x118D   (read via fcn.18001d940, 0xB5)
0x18001f276 0x5120 -> poll reg 0xC515
            else   -> poll reg 0xC555
```
loop ~100x with Sleep(1); logs "wait for command done timeout 0x%x" on failure.
This is a **control transfer**, not a bulk write. No frame-size is sent here.

### 7.3 screen on/off `fcn.18001f530`

Read-modify-write of one xdata bit, no `0xA6`:
```
0x9132, reg0x31(ctx+0x1A0)==5 -> addr 0xFB07 ; else -> addr 0xF037
read 1 byte (0xB5 via fcn.18001d940), set/clear a mask bit (screen on=clear, off=set),
write back via fcn.18001de50 == the 0xB6 xdata WRITE primitive:
SET_REPORT [0xB6, addrHi, addrLo, value, 0,0,0,0]
```
(NOTE: `fcn.18001de50` is the **0xB6 WRITE**, not a read; §1's table mislabels it.)

### 7.4 What "start screen for data size %d" actually is (worker, `fcn.18001c660`)

The log string `start screen for data size %d` (0x18009acb0) is emitted INSIDE
the bulk sender at `0x18001ca9e`, and it is **NOT** a separate control packet
carrying the JPEG size. The `%d` is just ctx-slot+0x1BC (the padded JPEG byte
count) printed to the log. The "start screen" handshake itself is simply:
```
0x18001cab6  call fcn.18001f530(ctx, dl=1)   ; screen_on
0x18001cac0  call fcn.18001f090(ctx, dl=1)   ; set_video_on  (A6 05 01)
0x18001cacc  mov  byte [rbx+0x1a8], 1         ; "started" latch
```
**The JPEG size is NOT sent over the wire anywhere.** No length prefix, no size
register. The size only appears in the host-side log. (This kills the theory that
a size handshake precedes the bulk write.) This handshake runs **after** the
first successful bulk write (it is gated on frame-count `ctx+0x228 >= 2` and the
0x1A8 latch), so it is a re-arm, not a precondition for frame #1.

### 7.5 THE pre-bulk gate (most likely cause of the timeout)

Before the bulk write, with `m_in_osd_state` (ctx+0x5A0) == 0 (normal host path),
the worker reads reg **0xF7E9** (0x9132; `0xF439` on other chips) and tests bit0:
```
0x18001c766  mov  edx, 0xf7e9
0x18001c77b  call fcn.18001d940              ; read 1 byte (0xB5)
0x18001c780  test byte [var], 1              ; bit0 = "is_osd_flushing"
0x18001c785  jne  0x18001c88c               ; bit0 SET  -> proceed to bulk send
             ; bit0 CLEAR -> "NOT is_osd_flushing, exit osd state":
0x18001c7aa  call fcn.18001f090(ctx,0)       ; video off
0x18001c7b4  call fcn.18001f530(ctx,0)       ; screen off
0x18001c7c5  call fcn.18001e640(ctx,0)       ; A6 04 00 (clear updated flag)
0x18001c7d9  call fcn.18001a840              ; apply_input_rect_change  <-- reprograms geometry
0x18001c7de  mov  eax, 0xfffffffc            ; return -4 (retry next tick) -- NO BULK SENT
```
**=> the device must report 0xF7E9 bit0 == 1 (`is_osd_flushing`, i.e. the frame
buffer is in host-fill / flushing mode) or the worker silently skips the bulk
write and just retries.** If our raw script blasts a JPEG to EP4 while the panel
is sitting in its boot/OSD/logo state (0xF7E9 bit0 == 0, not draining EP4), the
bulk OUT has nowhere to go and times out. That matches our symptom exactly.

`0xF7E9` bit0 is put into the "flushing/host" state by the init bring-up
(set_power_on -> set_video -> set_screen -> apply_input_rect, §7.7) plus the
`0xA6 04 01` "input updated" command. There is a second guard: if bit0==1 but
the device is also "mem_freezing" (reg **0xD042 bit3** on 0x9132, `0xF242` else)
and was flushing, the worker enters osd_state and `pool_clear`s instead of
sending. For a cold host-display bring-up you want: bit0(0xF7E9)=1,
bit3(0xD042)=0.

### 7.6 SetVideoParam side effects (`fcn.18001c380` resolver + ctx)

`MSDisplaySetVideoParam` / `fcn.18001c380` does **no device I/O by itself** -- it
only resolves width/height -> `hactive`(ctx+0x234), `vactive`(ctx+0x238),
`mode`(ctx+0x230) and sets ctx+0x23C=1 (see §3). The resolved values are what the
worker's `apply_input_rect_change` later programs into the chip via the `0xA6 01`
/ `0xA6 02` geometry commands (§7.7). So SetVideoParam is bookkeeping, but it is a
**precondition**: without it ctx+0x234/238/230 are stale and (a) the
"worker's resolution is inconsistant" guard at 0x18001ca06 aborts the send
(compares ctx+0x234 vs the frame's stored width at slot+0x1CC), and (b) the
geometry pushed to the panel is wrong. **Call SetVideoParam before SendPicture.**

### 7.7 apply_input_rect_change `fcn.18001a840` -- the geometry/format push

This is where the resolved mode actually reaches the chip. Sequence:
```
read 0xF7E9 bit0; if already flushing -> log & return (don't re-push)
if 0x1A8 latch: video_off + screen_off, clear latch, zero frame-count
if 0x596 set:   A6 04 00 (clear updated)
if state==3:
   fcn.18001cb50  pool_clear
   fcn.18001e800  set_transfer_mode  (A6 03 03)
   fmt = (hactive*vactive <= 0xE1000 && !fallback && jpeg_flag) ? 0x11 : 0x22
   fcn.18001eab0(ctx, mode=ctx+0x230, vactive=ctx+0x238, fmt)   ; A6 01 ... input rect+format
   fcn.18001eda0(ctx, mode=ctx+0x230, hactive=ctx+0x234, vactive=ctx+0x238) ; A6 02 ... output timing
   fcn.18001e640(ctx, 1)   ; A6 04 01  -> set "input updated" -> this is what flips 0xF7E9 into flushing
   set 0x596 = 1
```
So **`A6 01` (rect+fmt 0x11) + `A6 02` (timing) + `A6 04 01` (commit)** is the
register sequence that switches the panel into host-JPEG scanout. fmt byte
**0x11** is the JPEG/RGB path (used when jpeg_flag set and area <= 0xE1000),
**0x22** the larger raw path.

### 7.8 MSDisplayStart / init register writes `fcn.18001a1e0` (order)

1. `usb_claim_interface(handle, 3)`.
2. chip-id read (§7.1).  3. read Video Port, SDRAM type.
4. read 0xF7E9 ("is_osd_flushing at init state" check).
5. flash-read 32 bytes @ 0x1FE0 (0xF5) -> serial if begins `5A A5`.
6. `fcn.18001f340` **set_power_on**  -> `A6 07 01`, poll 0xC454 done.
7. `fcn.18001f090(0)` **set_video_on(0)** -> `A6 05 00`, poll 0x118D done.
8. `fcn.18001f530(0)` **set_screen_on(0)** -> read 0xF037/0xFB07, RMW, write 0xB6.
9. If reg0x31 (ctx+0x1A0) != 4:
   - read 0xF160 (0xB5), write back `val & 0xDF` (0xB6)   ; clear bit5
   - write **0xF031 = 0x34** (0xB6 xdata write)
   - `fcn.18001cec0` init_flash_gpio: write reg via 0xC5 (`mov dl,0xB0` ->
     `fcn.18001d0a0`), then 0xC6 burst `val & 0xFB`.
10. flash/custom-timing block: 0xFC50 (7B read), 0xFC60, 0xFC80, 0xF01F (APPEND
    mode for firmware-defined custom timing).

Init turns video/screen OFF (steps 7-8 pass 0); the panel is actually turned ON
+ put into flushing per-frame via the start-screen handshake (§7.4) and
apply_input_rect (§7.7).

### 7.9 CONCRETE ordered sequence to display one JPEG from a cold device

```
# --- open ---
set_configuration; usb_claim_interface(3)

# --- read chip id (ONE transfer) ---
SET_REPORT [B5 FF 00 00 00 00 00 00]
resp = GET_REPORT(A1,01,0300,len=8)
assert resp[4]==0x13 and resp[5]==0x0A          # chip 0x9132
jpeg = (resp[3]==0xD7)                            # only then is JPEG enabled

# --- init bring-up (mirror fcn.18001a1e0) ---
set_power_on:    SET_REPORT [A6 07 01 00 0 0 0 0]; poll reg 0xC454 bit0==0
set_video(0):    SET_REPORT [A6 05 00 00 0 0 0 0]; poll reg 0x118D bit0==0
set_screen(0):   v=reg_read(0xF037); reg_write_B6(0xF037, v|maskoff)
# (if reg0x31!=4): v=reg_read(0xF160); reg_write_B6(0xF160, v & 0xDF);
#                  reg_write_B6(0xF031, 0x34)

# --- set video param (resolves mode/hactive/vactive in ctx; needed for geometry+guard) ---
MSDisplaySetVideoParam(width,height)   # no device I/O, but required before SendPicture

# --- push geometry + switch panel to host-JPEG scanout (apply_input_rect_change) ---
set_transfer_mode: SET_REPORT [A6 03 03 00 0 0 0 0]
input_rect+fmt:    SET_REPORT [A6 01 modeHi modeLo vactHi vactLo 0x11 0]   # 0x11=JPEG
output_timing:     SET_REPORT [A6 02 modeLo 00 hactHi hactLo vactHi vactLo]
commit/updated:    SET_REPORT [A6 04 01 00 0 0 0 0]                         # flips 0xF7E9 bit0->1
screen_on:         v=reg_read(0xF037); reg_write_B6(0xF037, v & ~mask)      # backlight/output on
video_on:          SET_REPORT [A6 05 01 00 0 0 0 0]; poll 0x118D bit0==0

# --- GATE: wait until the panel is in flushing/host mode ---
while reg_read(0xF7E9) & 1 == 0:  re-do set_video_on(1)/apply_input_rect; sleep
# (worker refuses the bulk write until 0xF7E9 bit0 == 1)

# --- per frame ---
jpeg += b'\x00' * ((-len(jpeg)) & 3)             # pad to %4
usb_bulk_write(EP=0x04, jpeg, timeout=3000)
usb_bulk_write(EP=0x04, b'', timeout=3000)       # ZLP = end-of-frame
# (every ~frame, the worker re-issues screen_on + video_on = the "start screen" re-arm)
```

**Bottom line on the timeout:** the missing step is not a size handshake (there
is none). It is the **`0xA6` bring-up: set_power_on, set_transfer_mode (A6 03 03),
input_rect+fmt 0x11 (A6 01), output_timing (A6 02), commit (A6 04 01),
video_on (A6 05 01)** which together set **reg 0xF7E9 bit0 = 1**. The worker
hard-gates the bulk write on that bit; without it the panel never drains EP 0x04
and the bulk write times out. Verify 0xF7E9 bit0==1 before sending.
