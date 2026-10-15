#!/usr/bin/env python3
"""Userspace driver for the Jonsbo DS339 (USB 345f:9132, MacroSilicon).

Reverse-engineered from JONSBO-AIO's MSDISPLAYSDKWRRAPER.dll (libusb0 +
libjpeg-turbo 3.0.5) and live wine-harness stub captures.

Real hardware on this unit:
  - chip-id @0xF000=b7160a -> SDK product 0x912C, jpeg_flag=0 (RAW only)
  - Wine 912C path (stub_20260714_160237): 720x480 mode 2, fmt 0x11 RAW,
    screen reg **F004** (off=0, on=0x02), video-done poll **C555**, not F037.
  - Physical panel 376x960; SDK forces 720x480 when reg31==4. Default wire
    is 720x480 mode 2 (matches wine bulk frame). Override with --w/--h/--mode.
  - RAW RGB888 + 8-byte header/footer, FF->FE, BGR on wire (wine solid red:
    00 00 FE). Default order=bgr.
  - Gate: F439 (912C) / F7E9 (9132); this unit also sets F7E9 on A6 04.
  - Windows claims only MI_03; we claim HID 0 + bulk 3.

Deps: pyusb, pillow, numpy.  Permissions: ds339.rules
See wine-harness/ for SDK capture under Wine.
"""
from __future__ import annotations

import json
import sys
import time

import numpy as np
from PIL import Image, ImageDraw, ImageOps

VERSION = "0.1.0"
VID, PID = 0x345F, 0x9132
BULK_EP = 0x04

# Physical panel is 376x960 portrait. Default host wire is wine 720x480.
PANEL_W, PANEL_H = 376, 960
WIRE_W, WIRE_H = 720, 480
WIRE_MODE = 2

CTRL_OUT, CTRL_IN = 0x21, 0xA1
SET_REPORT, GET_REPORT = 0x09, 0x01
WVALUE = 0x0300

# A6 01 format byte (wine RAW path: 0x11; JPEG path: 0x22)
FMT_RAW = 0x11
FMT_JPEG = 0x22

# Host-flush gates (SDK cmovne product==9132)
GATE_9132 = 0xF7E9
GATE_OTHER = 0xF439

# Screen register: wine 912C uses F004; 9132 path uses F037 (PROTOCOL)
SCREEN_912C = 0xF004
SCREEN_9132 = 0xF037
# Command-done poll after A6 05: 912C stub uses C555; 9132 uses 118D
DONE_VIDEO_912C = 0xC555
DONE_VIDEO_9132 = 0x118D
DONE_POWER = 0xC454


class DS339:
    def __init__(self):
        import usb.core
        import usb.util

        self._usb = usb
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise RuntimeError(f"DS339 not found ({VID:04x}:{PID:04x})")

        # INF binds libusb0 to MI_03 only. Do not set_configuration (audio
        # ifaces, when present, are held by snd-usb-audio).
        for iface in (0, 3):
            try:
                if self.dev.is_kernel_driver_active(iface):
                    self.dev.detach_kernel_driver(iface)
            except (usb.core.USBError, NotImplementedError):
                pass

        cfg = self.dev.get_active_configuration()
        self.ep = None
        self._bulk_intf = None
        for intf in cfg:
            for ep in intf:
                if ep.bEndpointAddress == BULK_EP:
                    self.ep, self._bulk_intf = ep, intf
        if self.ep is None:
            raise RuntimeError(f"bulk EP {BULK_EP:#04x} missing")

        # Claim HID (control) + vendor bulk. SDK only claims 3; we need 0
        # for SET_REPORT when hid-generic is detached.
        try:
            usb.util.claim_interface(self.dev, 0)
        except usb.core.USBError:
            pass
        try:
            usb.util.claim_interface(self.dev, self._bulk_intf)
        except usb.core.USBError as e:
            raise RuntimeError(f"claim iface 3 failed: {e}") from e

        try:
            self.ep.clear_halt()
        except usb.core.USBError:
            pass

        self.width = WIRE_W
        self.height = WIRE_H
        self.mode = WIRE_MODE  # wine 720x480 uses mode 2
        self.channel_order = _CHANNEL_ORDER
        self.raw_header = _RAW_HEADER
        self.pixel_format = "rgb888"  # or "uyvy"
        self._ready = False
        self.product = 0
        self.gate_reg = GATE_OTHER
        self.screen_reg = SCREEN_912C
        self.done_video = DONE_VIDEO_912C
        try:
            _cid, _jpeg, _base, product = self.chip_id()
            self.product = product
            self._apply_product(product)
        except Exception:
            pass

    def _apply_product(self, product: int) -> None:
        self.product = product
        if product == 0x9132:
            self.gate_reg = GATE_9132
            self.screen_reg = SCREEN_9132
            self.done_video = DONE_VIDEO_9132
        else:
            # 912C and other non-9132: wine stub uses F004 + C555
            self.gate_reg = GATE_OTHER
            self.screen_reg = SCREEN_912C
            self.done_video = DONE_VIDEO_912C

    # --- HID control (interface 0) -------------------------------------------
    def _set_report(self, payload):
        pkt = bytes(payload) + bytes(8 - len(payload))
        self.dev.ctrl_transfer(CTRL_OUT, SET_REPORT, WVALUE, 0, pkt, 1000)

    def _get_report(self):
        return bytes(self.dev.ctrl_transfer(CTRL_IN, GET_REPORT, WVALUE, 0, 8, 1000))

    def reg_read(self, addr: int) -> int:
        self._set_report([0xB5, (addr >> 8) & 0xFF, addr & 0xFF])
        return self._get_report()[3]

    def reg_write_b6(self, addr: int, value: int):
        self._set_report([0xB6, (addr >> 8) & 0xFF, addr & 0xFF, value & 0xFF])
        self._get_report()

    def _c5(self, reg: int) -> bytes:
        self._set_report([0xC5, reg & 0xFF])
        return self._get_report()

    def _c6(self, reg: int, value: int) -> None:
        self._set_report([0xC6, reg & 0xFF, value & 0xFF])

    def _poll_done(self, addr: int, timeout: float = 0.5) -> int:
        """Poll command-done register until bit0 clear (wine after A6 05/07)."""
        t0 = time.time()
        last = 0xFF
        while time.time() - t0 < timeout:
            try:
                last = self.reg_read(addr)
                if (last & 1) == 0:
                    return last
            except self._usb.core.USBError:
                pass
            time.sleep(0.01)
        return last

    def cmd(self, *payload):
        """Fire-and-forget A6 command family."""
        self._set_report([0xA6, *payload])

    def write6(self, addr: int, data6):
        data6 = list(data6) + [0] * (6 - len(data6))
        self._set_report([0xA6, addr & 0xFF, *data6[:6]])

    def chip_id(self):
        """Read chip bytes and classify like SDK fcn.18001f660.

        Returns (cid3, jpeg_flag, base_addr, product_id).
        This unit: b7 16 0a @0xF000 -> product 0x912C, jpeg=False.
        """
        for base in (0xFF00, 0xF000):
            self._set_report([0xB5, (base >> 8) & 0xFF, base & 0xFF])
            r = self._get_report()
            cid = bytes(r[3:6])
            if cid == b"\x00\x00\x00":
                continue
            b0, b1, b2 = cid[0], cid[1], cid[2]
            jpeg, product = False, 0
            if b1 == 0x13 and b2 == 0x3A:
                jpeg, product = True, 0x9133
            elif b1 == 0x13 and b2 == 0x0A:
                jpeg = b0 == 0xD7
                product = 0x9132
            elif b1 == 0x16 and b2 == 0x0A:
                if b0 == 0xB7:
                    product = 0x912C
                elif b0 == 0xA7:
                    product = 0x912A
                else:
                    product = 0x9120
            elif b0 == 0xC5 and b1 == 0x12:
                jpeg, product = True, 0x5120
            return cid, jpeg, base, product
        return b"\x00\x00\x00", False, 0xFF00, 0

    def _gate_ok(self) -> bool:
        """True if either product gate or F7E9 shows host-flushing.

        Wine 912C polls F439; this panel's A6 04 also sets F7E9 bit0. Accept
        either so we do not stall when F439 stays 0 on real hardware.
        """
        try:
            if self.reg_read(self.gate_reg) & 1:
                return True
        except self._usb.core.USBError:
            pass
        if self.gate_reg != GATE_9132:
            try:
                if self.reg_read(GATE_9132) & 1:
                    return True
            except self._usb.core.USBError:
                pass
        return False

    def _wait_hotplug(self, timeout: float = 5.0) -> int:
        """Wait for reg 0x32 connected+stable (wine: 0x09) before geometry.

        Cold bulk without this often NAKs for a full URB timeout, and pyusb
        returns a tiny partial (~1024 B) without raising. Crawling that way
        is what made first colour take ~30 s.

        This unit sometimes sticks at 0x01 (connected, not stable). Prefer
        stable (bit3), but if connected for ~0.5 s without stable, proceed
        rather than always burning the full timeout.
        """
        t0 = time.time()
        last = 0
        connected_since: float | None = None
        while time.time() - t0 < timeout:
            try:
                last = self.reg_read(0x32)
            except self._usb.core.USBError:
                time.sleep(0.05)
                continue
            # bit0 connected, bit3 stable (0x09 when both set)
            if (last & 0x09) == 0x09 or (last & 0x08):
                return last
            if last & 0x01:
                if connected_since is None:
                    connected_since = time.time()
                elif time.time() - connected_since >= 0.5:
                    return last
            else:
                connected_since = None
            time.sleep(0.05)
        return last

    def _probe_bulk(self, timeout: int = 500) -> bool:
        """True if EP4 accepts a max-packet write quickly (no geometry)."""
        try:
            self.ep.clear_halt()
        except self._usb.core.USBError:
            pass
        try:
            n = int(self.ep.write(b"\x00" * 512, timeout=timeout))
            return n > 0
        except self._usb.core.USBError:
            try:
                self.ep.clear_halt()
            except self._usb.core.USBError:
                pass
            return False

    def _recover_bulk(self):
        """Clear EP halt after a stall. Avoid re-commit if already flushing.

        Re-issuing A6 04 01 while F7E9 is already set has been observed to
        permanently NAK EP4 until the device is replugged.
        """
        try:
            self.ep.clear_halt()
        except self._usb.core.USBError:
            pass
        if not self._gate_ok():
            try:
                self.write6(0x04, [1, 0, 0, 0, 0, 0])
            except self._usb.core.USBError:
                pass
        time.sleep(0.05)

    # --- bring-up -----------------------------------------------------------
    def ready(self, jpeg: bool | None = None):
        """Prepare device for streaming.

        Live 912C hazard: after a fresh plug EP4 accepts 512 B immediately and
        F7E9 is often already set. Re-running wine's full "screen off + geometry
        re-push" sequence can permanently NAK EP4 until the device is replugged.
        So we probe first and take a minimal path when the pipe is already live.
        """
        if jpeg is None:
            if self._ready:
                return
            jpeg = False
        elif self._ready and getattr(self, "_jpeg", None) == jpeg:
            return

        try:
            _cid, _j, _b, product = self.chip_id()
            self._apply_product(product)
        except self._usb.core.USBError:
            pass

        fmt = FMT_JPEG if jpeg else FMT_RAW
        w, h, mode = self.width, self.height, self.mode
        if mode == 0 and (w, h) == (720, 480):
            mode = 2
        hh, hl = (w >> 8) & 0xFF, w & 0xFF
        vh, vl = (h >> 8) & 0xFF, h & 0xFF

        # Probe BEFORE any A6 that might brick the pipe.
        bulk_ok = self._probe_bulk()
        already = self._gate_ok()

        if bulk_ok and already:
            # Live path: do not touch A6 07/05/04 or F004. On this 912C unit,
            # A6 07 power-on (and geometry re-push) while already flushing has
            # been observed to permanently NAK EP4 until replug. Just stream.
            pass
        else:
            # Full wine-ish bring-up only when pipe is cold or not flushing.
            self.write6(0x07, [0x01, 0x02, 0, 0, 0, 0])
            self._poll_done(DONE_POWER, 0.5)
            self.write6(0x05, [0, 0, 0, 0, 0, 0])
            self._poll_done(self.done_video, 0.5)
            try:
                self.reg_write_b6(self.screen_reg, 0)
            except self._usb.core.USBError:
                pass
            try:
                f160 = self.reg_read(0xF160)
                self.reg_write_b6(0xF160, f160 & 0xDF)
                self.reg_write_b6(0xF031, 0x34)
            except self._usb.core.USBError:
                pass
            try:
                self._c5(0xB0)
                self._c6(0xB0, 0xDC)
                self._c5(0xA0)
                self._c6(0xA0, 0x00)
                self.reg_write_b6(0xF016, 0)
            except self._usb.core.USBError:
                pass
            try:
                freeze = 0xD042 if self.product == 0x9132 else 0xF242
                v = self.reg_read(freeze)
                if v & 0x08:
                    self.reg_write_b6(freeze, v & ~0x08)
            except self._usb.core.USBError:
                pass
            self._wait_hotplug(2.0)

            self.write6(0x03, [3, 0, 0, 0, 0, 0])
            self.write6(0x01, [hh, hl, vh, vl, fmt, 0])
            self.write6(0x02, [mode & 0xFF, 0, hh, hl, vh, vl])
            self.write6(0x04, [1, 0, 0, 0, 0, 0])
            for _ in range(30):
                if self._gate_ok():
                    break
                time.sleep(0.05)
            time.sleep(0.05)
            if not self._probe_bulk():
                raise RuntimeError(
                    "bulk EP4 dead after geometry; unplug/replug the DS339"
                )

        try:
            self.ep.clear_halt()
        except self._usb.core.USBError:
            pass

        self._jpeg = jpeg
        self._fmt = fmt
        self._armed_video = False
        self._frame_i = 0
        self._ready = True

    def _arm_video(self):
        """Enable host scanout after first bulk (wine 912C: F004=0x02 + A6 05 01).

        Earlier we wrote F037=1; that is the 9132 path. This unit (912C) uses
        F004, and wine sets it to 0x02 (not 0x01) after the first frame.
        """
        if self._armed_video:
            return
        try:
            if self.screen_reg == SCREEN_912C:
                self.reg_write_b6(self.screen_reg, 0x02)
            else:
                self.reg_write_b6(self.screen_reg, 0x01)
        except self._usb.core.USBError:
            pass
        # Also assert F037 bit0; some firmware paths look at both.
        try:
            if self.screen_reg != SCREEN_9132:
                v = self.reg_read(SCREEN_9132)
                self.reg_write_b6(SCREEN_9132, v | 0x01)
        except self._usb.core.USBError:
            pass
        self.write6(0x05, [1, 0, 0, 0, 0, 0])
        self._poll_done(self.done_video, 0.5)
        self._armed_video = True

    # --- frame encode --------------------------------------------------------
    def _canvas_wire(self, img: Image.Image) -> Image.Image:
        """Fit portrait content into 376x960, rotate to 960x376 wire."""
        img = ImageOps.exif_transpose(img).convert("RGB")
        portrait = Image.new("RGB", (PANEL_W, PANEL_H), "black")
        fit = img.copy()
        fit.thumbnail((PANEL_W, PANEL_H))
        portrait.paste(fit, ((PANEL_W - fit.width) // 2, (PANEL_H - fit.height) // 2))
        return portrait.rotate(-90, expand=True)  # -> 960x376

    def frame(self, img: Image.Image) -> bytes:
        wire = self._canvas_wire(img)
        if wire.size != (self.width, self.height):
            wire = wire.resize((self.width, self.height), Image.Resampling.BILINEAR)
        if getattr(self, "_jpeg", False):
            import io
            buf = io.BytesIO()
            h = (wire.height + 7) & ~7
            if h != wire.height:
                c = Image.new("RGB", (wire.width, h), "black")
                c.paste(wire, (0, 0))
                wire = c
            wire.save(buf, format="JPEG", quality=95, subsampling="4:2:2")
            data = buf.getvalue()
            return data + b"\x00" * ((-len(data)) & 3)
        arr = np.asarray(wire)
        hdr = getattr(self, "raw_header", _RAW_HEADER)
        order = getattr(self, "channel_order", None)
        fmt = getattr(self, "pixel_format", "rgb888")
        if fmt == "uyvy":
            return _uyvy_frame(arr, self.width, self.height, header=hdr)
        if fmt == "bgra":
            return _bgra_frame(arr, self.width, self.height, order=order, header=hdr)
        return _rgb888_frame(arr, self.width, self.height, order=order, header=hdr)

    def _bulk_write_all(self, data: bytes, timeout: int = 3000):
        """Write full buffer in fixed chunks.

        SDK uses 3000 ms per usb_bulk_write (frame + ZLP). Linux often
        short-transfers large URBs (1024 B is common here). Always chunk so
        each submit stays under the flaky size; continue from any short write.
        Chunk = 8 * lcm(512, 3) = 12288 so boundaries stay packet- and
        pixel-aligned.

        pyusb/libusb returns a partial length on TIMEOUT without raising when
        any bytes moved. Treating that as normal progress made the first cold
        frame crawl at ~1 KiB per timeout (~30 s). Treat near-timeout shorts
        as a stall so write_frame can recover and retry the whole frame.

        On hard timeout: clear_halt and retry this chunk once. That second
        URB is what wakes this unit's cold EP4 (reg 0x32 stays 0x01, never
        the wine 0x09). Skipping the inner retry left the pipe dead.
        """
        # Live unit often accepts only wMaxPacketSize (512) per URB when the
        # pipe is cold; larger submits timeout-short. Stay at 512.
        chunk = 512
        off = 0
        timeout_s = timeout / 1000.0
        while off < len(data):
            part = data[off : off + chunk]
            t0 = time.time()
            try:
                n = int(self.ep.write(part, timeout=timeout))
            except self._usb.core.USBError:
                try:
                    self.ep.clear_halt()
                except self._usb.core.USBError:
                    pass
                time.sleep(0.02)
                t0 = time.time()
                n = int(self.ep.write(part, timeout=timeout))
            dt = time.time() - t0
            if n <= 0:
                raise self._usb.core.USBError(
                    f"bulk write stalled at {off}/{len(data)}"
                )
            # Timeout-with-partial of less than one full packet: stall.
            # Short success (n==512 of larger part) is normal; advance.
            if n < len(part) and dt >= timeout_s * 0.85 and n < 512:
                try:
                    self.ep.clear_halt()
                except self._usb.core.USBError:
                    pass
                raise self._usb.core.USBError(
                    f"bulk timeout short n={n}/{len(part)} at {off}"
                )
            off += n

    def write_frame(self, data: bytes):
        # Occasional scanout/keepalive (not every frame: HID+bulk stalls).
        self._frame_i = getattr(self, "_frame_i", 0) + 1
        if self._frame_i == 1 or self._frame_i % 60 == 0:
            try:
                if not self._gate_ok():
                    self.write6(0x04, [1, 0, 0, 0, 0, 0])
                    time.sleep(0.05)
            except self._usb.core.USBError:
                pass

        # Cold EP4 needs one failed bulk + recover before line-rate frames.
        # Measured: first frame ~6 s (two 3 s URB windows), then ~30 ms.
        last_err: Exception | None = None
        for attempt in range(4):
            try:
                self._bulk_write_all(data, timeout=3000 if attempt == 0 else 5000)
                last_err = None
                break
            except self._usb.core.USBError as e:
                last_err = e
                self._recover_bulk()
                if attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
        if last_err is not None:
            raise last_err

        # ZLP end-of-frame (wine: second usb_bulk_write size=0, timeout 3000)
        try:
            self.ep.write(b"", timeout=1000)
        except self._usb.core.USBError:
            pass

        # Wine 912C: after first bulk, F004=0x02 + A6 05 01 (see _arm_video).
        if not self._armed_video:
            self._arm_video()
        # Keep freeze bit clear; if it latches, bulk can succeed while logo stays.
        if self._frame_i == 1 or self._frame_i % 30 == 0:
            try:
                freeze = 0xD042 if self.product == 0x9132 else 0xF242
                v = self.reg_read(freeze)
                if v & 0x08:
                    self.reg_write_b6(freeze, v & ~0x08)
            except self._usb.core.USBError:
                pass
        if self._frame_i % 60 == 0:
            try:
                self.reg_read(0x32)  # hotplug keepalive
            except self._usb.core.USBError:
                pass

    def show(self, img: Image.Image, hold: float = 0.0):
        self.ready()
        f = self.frame(img)
        if hold <= 0:
            self.write_frame(f)
            return
        t0 = time.time()
        while time.time() - t0 < hold:
            self.write_frame(f)
            time.sleep(0.05)

    def stream_bytes(self, data: bytes, fps: float = 15):
        self.ready()
        delay = 1.0 / max(fps, 1)
        n = 0
        try:
            while True:
                t0 = time.time()
                self.write_frame(data)
                n += 1
                if n == 1:
                    print(f"first frame ok in {time.time() - t0:.2f}s", flush=True)
                elif n % 30 == 0:
                    print(f"frames: {n}", flush=True)
                time.sleep(delay)
        except KeyboardInterrupt:
            print(f"\nstopped after {n} frames")


# Wire channel order. Live pure-wire + gbr trial (2026-07-14):
#   FE,0,0 -> blue   0,FE,0 -> teal   0,0,FE -> purple
# i.e. panel byte0=B, byte1~G, byte2=R  => pack "bgr" (matches SDK/wine).
# gbr put green on FE,0,0 and showed blue — confirmed byte0 is blue.
# Override: --order …
_CHANNEL_ORDER = "bgr"

# SDK raw framing always includes 8-byte header + footer (wine frame dump).
# Override: --no-header / --header
_RAW_HEADER = True

_ORDERS = {
    "rgb": (0, 1, 2),
    "bgr": (2, 1, 0),
    "rbg": (0, 2, 1),
    "gbr": (1, 2, 0),
    "grb": (1, 0, 2),
    "brg": (2, 0, 1),
}


def _rgb888_frame(
    rgb: np.ndarray,
    width: int,
    height: int,
    order: str | None = None,
    header: bool | None = None,
) -> bytes:
    """Packed 8-bit channels (FF->FE), optional SDK header/footer.

    Header (ms912x / SDK builder), when enabled:
      FF 00 00 00 00 | (width>>4) | ((height>>8)&0xF)|((width&0xF)<<4) | height&0xFF
    """
    assert rgb.shape == (height, width, 3), rgb.shape
    order = (order or _CHANNEL_ORDER).lower()
    if order not in _ORDERS:
        raise ValueError(f"unknown channel order {order!r}, want {sorted(_ORDERS)}")
    i0, i1, i2 = _ORDERS[order]
    pix = np.empty_like(rgb)
    pix[..., 0] = rgb[..., i0]
    pix[..., 1] = rgb[..., i1]
    pix[..., 2] = rgb[..., i2]
    # 0xFF reserved for header/footer markers when those are used
    pix = np.minimum(pix, 254).astype(np.uint8)
    body = pix.tobytes()

    if header is None:
        header = _RAW_HEADER
    if not header:
        return body

    hdr = bytes([
        0xFF, 0x00, 0x00, 0x00, 0x00,
        (width >> 4) & 0xFF,
        ((height >> 8) & 0x0F) | ((width & 0x0F) << 4),
        height & 0xFF,
    ])
    footer = bytes([0xFF, 0xC0, 0, 0, 0, 0, 0, 0])
    return hdr + body + footer


def _pix0(frame: bytes, header: bool | None = None) -> tuple[int, int, int]:
    """First pixel triple in a frame buffer."""
    if header is None:
        header = _RAW_HEADER
    off = 8 if header else 0
    return frame[off], frame[off + 1], frame[off + 2]


def _uyvy_frame(
    rgb: np.ndarray,
    width: int,
    height: int,
    header: bool | None = None,
) -> bytes:
    """BT.601 full-range UYVY (2 B/px) + optional SDK header/footer.

    Used when area > 0xE1000 in the SDK; optional experiment for 912C if
    RGB888 is mis-decoded. Width must be even.
    """
    assert rgb.shape == (height, width, 3), rgb.shape
    if width % 2:
        raise ValueError("UYVY needs even width")
    r = rgb[..., 0].astype(np.float32)
    g = rgb[..., 1].astype(np.float32)
    b = rgb[..., 2].astype(np.float32)
    y = 0.299 * r + 0.587 * g + 0.114 * b
    u = -0.169 * r - 0.331 * g + 0.500 * b + 128.0
    v = 0.500 * r - 0.419 * g - 0.081 * b + 128.0
    y = np.clip(y, 0, 254).astype(np.uint8)
    u = np.clip(u, 0, 254).astype(np.uint8)
    v = np.clip(v, 0, 254).astype(np.uint8)
    # average chroma per pair
    u2 = ((u[:, 0::2].astype(np.uint16) + u[:, 1::2].astype(np.uint16)) // 2).astype(
        np.uint8
    )
    v2 = ((v[:, 0::2].astype(np.uint16) + v[:, 1::2].astype(np.uint16)) // 2).astype(
        np.uint8
    )
    y0 = y[:, 0::2]
    y1 = y[:, 1::2]
    out = np.empty((height, width // 2, 4), dtype=np.uint8)
    out[..., 0] = u2
    out[..., 1] = y0
    out[..., 2] = v2
    out[..., 3] = y1
    body = out.tobytes()
    if header is None:
        header = _RAW_HEADER
    if not header:
        return body
    hdr = bytes([
        0xFF, 0x00, 0x00, 0x00, 0x00,
        (width >> 4) & 0xFF,
        ((height >> 8) & 0x0F) | ((width & 0x0F) << 4),
        height & 0xFF,
    ])
    footer = bytes([0xFF, 0xC0, 0, 0, 0, 0, 0, 0])
    return hdr + body + footer


def _bgra_frame(
    rgb: np.ndarray,
    width: int,
    height: int,
    order: str | None = None,
    header: bool | None = None,
) -> bytes:
    """BGRA8888 (4 B/px) experiment; SDK uses 3 B/px at this size."""
    assert rgb.shape == (height, width, 3), rgb.shape
    order = (order or _CHANNEL_ORDER).lower()
    i0, i1, i2 = _ORDERS[order]
    bgra = np.empty((height, width, 4), dtype=np.uint8)
    bgra[..., 0] = np.minimum(rgb[..., i0], 254)
    bgra[..., 1] = np.minimum(rgb[..., i1], 254)
    bgra[..., 2] = np.minimum(rgb[..., i2], 254)
    bgra[..., 3] = 254
    body = bgra.tobytes()
    if header is None:
        header = _RAW_HEADER
    if not header:
        return body
    hdr = bytes([
        0xFF, 0x00, 0x00, 0x00, 0x00,
        (width >> 4) & 0xFF,
        ((height >> 8) & 0x0F) | ((width & 0x0F) << 4),
        height & 0xFF,
    ])
    footer = bytes([0xFF, 0xC0, 0, 0, 0, 0, 0, 0])
    return hdr + body + footer


def _solid_frame(
    rgb: tuple[int, int, int],
    width: int,
    height: int,
    order: str | None = None,
    header: bool | None = None,
    pixel_format: str = "rgb888",
) -> bytes:
    """Solid colour at wire size (no portrait/rotate)."""
    arr = np.empty((height, width, 3), dtype=np.uint8)
    arr[..., 0] = rgb[0]
    arr[..., 1] = rgb[1]
    arr[..., 2] = rgb[2]
    if pixel_format == "uyvy":
        return _uyvy_frame(arr, width, height, header=header)
    if pixel_format == "bgra":
        return _bgra_frame(arr, width, height, order=order, header=header)
    return _rgb888_frame(arr, width, height, order=order, header=header)


def _wire_solid_frame(
    b0: int,
    b1: int,
    b2: int,
    width: int,
    height: int,
    header: bool | None = None,
) -> bytes:
    """Solid wire triple, no channel remapping (byte0,byte1,byte2 as sent)."""
    arr = np.empty((height, width, 3), dtype=np.uint8)
    arr[..., 0] = b0
    arr[..., 1] = b1
    arr[..., 2] = b2
    return _rgb888_frame(arr, width, height, order="rgb", header=header)


def _gradient() -> Image.Image:
    g = np.zeros((PANEL_H, PANEL_W, 3), np.uint8)
    g[..., 0] = np.linspace(0, 255, PANEL_W)[None, :]
    g[..., 1] = np.linspace(0, 255, PANEL_H)[:, None]
    g[..., 2] = 128
    return Image.fromarray(g)


def _quadrants() -> Image.Image:
    img = Image.new("RGB", (PANEL_W, PANEL_H), "black")
    d = ImageDraw.Draw(img)
    w, h = PANEL_W, PANEL_H
    d.rectangle([0, 0, w // 2, h // 2], fill=(255, 0, 0))
    d.rectangle([w // 2, 0, w, h // 2], fill=(0, 255, 0))
    d.rectangle([0, h // 2, w // 2, h], fill=(0, 0, 255))
    d.rectangle([w // 2, h // 2, w, h], fill=(255, 255, 0))
    d.rectangle([0, 0, 40, 40], fill=(255, 255, 255))
    return img


HELP = """\
usage: ds339 [command] [options]
  schema [command]   print the CLI Spec document and exit
  version            print the version
  probe              read chip identity
  calibrate          cycle solid colours on the panel
  hunt               cycle wire patterns
  color              stream one solid colour
  image <path>       show an image
  stream [path]      stream an image or the quadrant pattern
  quad               stream the quadrant pattern
  test               stream a gradient (default when no command is given)
  -o, --output FMT   auto, text, or json. auto stays text on a pipe.
  -h, --help         show this help

schema, version, and help do not open the USB device.
"""

_COMMANDS = (
    {
        "name": "schema",
        "description": "Print this CLI Spec document. schema <command> returns the same document filtered to that command.",
        "effects": "read_only",
        "output_kind": "opaque",
        "media_type": "application/json",
    },
    {
        "name": "version",
        "description": "Print the ds339 version.",
        "effects": "read_only",
        "cardinality": "single",
        "output_fields": [{"name": "version", "type": "string"}],
    },
    {
        "name": "probe",
        "description": "Read chip identity and a sample of registers. Needs the USB device. Stdout stays the text report.",
        "effects": "read_only",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "calibrate",
        "description": "Cycle solid colours on the panel. A retry is not safe. Stdout stays the step lines.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "hunt",
        "description": "Cycle wire patterns on the panel. A retry is not safe. Stdout stays the step lines.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "color",
        "description": "Stream one solid colour until interrupted. A retry is not safe.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "image",
        "description": "Show one image file on the panel. A retry is not safe.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "stream",
        "description": "Stream an image, or the quadrant pattern when no path is given. A retry is not safe.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "quad",
        "description": "Stream the quadrant pattern. A retry is not safe.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
    {
        "name": "test",
        "description": "Stream a gradient. This is the command when no command word is given. A retry is not safe.",
        "effects": "non_idempotent",
        "output_kind": "opaque",
        "media_type": "text/plain",
    },
)


def _usage(message: str, *, json_mode: bool) -> None:
    print(message, file=sys.stderr)
    if json_mode:
        print(
            '{"error":{"kind":"usage","message":"invalid arguments"}}',
            file=sys.stderr,
        )
    raise SystemExit(2)


def _take_output(argv: list[str]) -> tuple[list[str], str]:
    mode = "auto"
    out: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-o", "--output"):
            if i + 1 >= len(argv):
                _usage("--output requires auto, text, or json", json_mode=False)
            mode = argv[i + 1]
            i += 2
        elif arg.startswith("--output="):
            mode = arg.split("=", 1)[1]
            i += 1
        else:
            out.append(arg)
            i += 1
        if mode not in ("auto", "text", "json"):
            _usage("--output requires auto, text, or json", json_mode=False)
    return out, mode


def _selected(name: str, path: str) -> bool:
    if path == "":
        return True
    if name == path:
        return True
    return name.startswith(path + " ")


def _schema_document(path: str) -> dict[str, object]:
    commands = []
    for cmd in _COMMANDS:
        if _selected(str(cmd["name"]), path):
            commands.append(cmd)
    if not commands:
        raise KeyError(path)
    return {
        "clispec": "0.3",
        "name": "ds339",
        "version": VERSION,
        "description": "Userspace driver for the Jonsbo DS339 panel.",
        "output": {"tty": "text", "piped": "text"},
        "global_args": [
            {
                "name": "--output",
                "short": "-o",
                "type": "string",
                "required": False,
                "description": "Before the command. auto stays text when piped.",
                "default": "auto",
                "enum": ["auto", "text", "json"],
            }
        ],
        "commands": commands,
        "errors": [
            {
                "kind": "usage",
                "exit_code": 2,
                "retryable": False,
                "description": "The arguments are not valid.",
            },
            {
                "kind": "failure",
                "exit_code": 1,
                "retryable": True,
                "description": "The command failed, including a missing USB device.",
            },
        ],
    }


def _emit_schema(rest: list[str], *, json_mode: bool) -> None:
    if any(part.startswith("-") for part in rest):
        _usage("usage: ds339 schema [command]", json_mode=json_mode)
    path = " ".join(rest)
    try:
        doc = _schema_document(path)
    except KeyError:
        _usage("unknown command path", json_mode=json_mode)
    print(json.dumps(doc, separators=(",", ":")))


def main(argv: list[str]) -> None:
    args, mode = _take_output(list(argv))
    json_mode = mode == "json"
    try:
        _run(args, json_mode=json_mode)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        if json_mode:
            print(
                '{"error":{"kind":"failure","message":"command failed"}}',
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        raise


def _run(argv: list[str], *, json_mode: bool) -> None:
    cmd = argv[0] if argv else "test"
    if cmd in ("-h", "--help", "help"):
        print(HELP)
        return
    if cmd == "schema":
        _emit_schema(argv[1:], json_mode=json_mode)
        return
    if cmd == "version":
        if json_mode:
            print(json.dumps({"version": VERSION}, separators=(",", ":")))
        else:
            print(f"ds339 {VERSION}")
        return

    # Geometry flags before open (for --uyvy guard without claiming USB)
    w = WIRE_W
    h = WIRE_H
    mode_cli = None
    # Exact wine-harness geometry that produced a valid raw frame (BGR red)
    if "--sdk" in argv:
        w, h, mode_cli = 720, 480, 2
    if "--w" in argv:
        w = int(argv[argv.index("--w") + 1])
    if "--h" in argv:
        h = int(argv[argv.index("--h") + 1])
    if "--uyvy" in argv and "--force" not in argv:
        area = w * h
        print(
            f"warning: UYVY is only used by the SDK when area > 0xE1000 "
            f"(921600). This geometry is {w}x{h}={area} (RGB888 path). "
            f"Half-size frames cause blink/glitch (e.g. green/teal). "
            f"Use RGB888+bgr (default). Pass --force to try UYVY anyway.",
            flush=True,
        )
        if area <= 0xE1000:
            print("refusing --uyvy without --force", flush=True)
            return

    d = DS339()
    d.width = w
    d.height = h
    if mode_cli is not None:
        d.mode = mode_cli

    if "--mode" in argv:
        d.mode = int(argv[argv.index("--mode") + 1], 0)
    if "--order" in argv:
        d.channel_order = argv[argv.index("--order") + 1].lower()
    if "--header" in argv:
        d.raw_header = True
    if "--no-header" in argv:
        d.raw_header = False
    if "--uyvy" in argv:
        d.pixel_format = "uyvy"
    if "--rgb888" in argv:
        d.pixel_format = "rgb888"
    if "--bgra" in argv:
        d.pixel_format = "bgra"

    if cmd == "probe":
        cid, jpeg, base, product = d.chip_id()
        d._apply_product(product)
        print(
            f"chip-id @{base:#06x} = {cid.hex()} jpeg={jpeg} "
            f"product={product:#06x} gate={d.gate_reg:#06x} "
            f"screen={d.screen_reg:#06x} done_v={d.done_video:#06x}"
        )
        print(f"config ifaces={d.dev.get_active_configuration().bNumInterfaces}")
        for a in (
            0x30, 0x31, 0x32, 0x33, 0xF7E9, 0xF439, 0xF004, 0xF037,
            0xF160, 0xF031, 0xF242, 0xD042,
        ):
            try:
                print(f"  reg {a:#06x} = {d.reg_read(a):#04x}")
            except Exception as e:
                print(f"  reg {a:#06x} ERR {e}")
        fw = _solid_frame((255, 0, 0), 720, 480, order="bgr", header=True)
        print(
            f"default wire={d.width}x{d.height} mode={d.mode} "
            f"solid-red bgr pix0={fw[8:11].hex()} (wine=0000fe)"
        )
        return

    # Default is RAW. Pass --jpeg only if you know the chip decodes it.
    use_jpeg = "--jpeg" in argv

    if cmd == "calibrate":
        # Black gap + pure wire + ordered primaries. Report what you see.
        use_hdr = d.raw_header
        print(
            f"calibrate wire={d.width}x{d.height} order={d.channel_order} "
            f"header={use_hdr} (Ctrl-C stop early)",
            flush=True,
        )
        d.ready(jpeg=False)

        def hold(label: str, data: bytes, secs: float = 3.0) -> None:
            p = _pix0(data, use_hdr)
            print(
                f">>> {label}  wire_px={p}  bytes={len(data)}  ({secs:.0f}s)",
                flush=True,
            )
            t0 = time.time()
            while time.time() - t0 < secs:
                d.write_frame(data)
                time.sleep(0.03)

        hold("BLACK", _solid_frame((0, 0, 0), d.width, d.height, order="rgb", header=use_hdr), 1.5)
        hold("WIRE 254,0,0", _wire_solid_frame(254, 0, 0, d.width, d.height, header=use_hdr))
        hold("WIRE 0,254,0", _wire_solid_frame(0, 254, 0, d.width, d.height, header=use_hdr))
        hold("WIRE 0,0,254", _wire_solid_frame(0, 0, 254, d.width, d.height, header=use_hdr))
        hold("WIRE white", _wire_solid_frame(254, 254, 254, d.width, d.height, header=use_hdr))
        for order in ("gbr", "bgr", "rgb"):
            for name, rgb in (("RED", (255, 0, 0)), ("GREEN", (0, 255, 0)), ("BLUE", (0, 0, 255))):
                f = _solid_frame(rgb, d.width, d.height, order=order, header=use_hdr)
                hold(f"order={order} {name} RGB{rgb}", f, 2.5)
        hold("BLACK done", _solid_frame((0, 0, 0), d.width, d.height, order="rgb", header=use_hdr), 1.0)
        print("calibrate finished — reply with colour for each >>> line", flush=True)
        return

    if cmd == "hunt":
        # Cycle wire patterns so you can spot pure red (or closest).
        use_hdr = d.raw_header
        secs = float(argv[argv.index("--secs") + 1]) if "--secs" in argv else 2.5
        print(
            f"hunt wire={d.width}x{d.height} mode={d.mode} header={use_hdr} "
            f"secs/step={secs} (Ctrl-C stop)",
            flush=True,
        )
        d.ready(jpeg=False)
        # black first to clear residual
        patterns: list[tuple[str, bytes]] = [
            ("BLACK", _wire_solid_frame(0, 0, 0, d.width, d.height, header=use_hdr)),
        ]
        for a in (254, 200, 128):
            patterns.append((f"WIRE {a},0,0", _wire_solid_frame(a, 0, 0, d.width, d.height, header=use_hdr)))
            patterns.append((f"WIRE 0,{a},0", _wire_solid_frame(0, a, 0, d.width, d.height, header=use_hdr)))
            patterns.append((f"WIRE 0,0,{a}", _wire_solid_frame(0, 0, a, d.width, d.height, header=use_hdr)))
        # try to cancel blue from purple (if 0,0,FE = R+B bleed)
        for g in (0, 40, 80):
            for b0 in (0, 40, 80):
                patterns.append(
                    (
                        f"WIRE {b0},{g},254",
                        _wire_solid_frame(b0, g, 254, d.width, d.height, header=use_hdr),
                    )
                )
        patterns.append(
            ("RGB red bgr", _solid_frame((255, 0, 0), d.width, d.height, order="bgr", header=use_hdr))
        )
        patterns.append(
            ("RGB red rgb", _solid_frame((255, 0, 0), d.width, d.height, order="rgb", header=use_hdr))
        )
        try:
            for label, data in patterns:
                p = data[8:11] if use_hdr else data[0:3]
                print(f">>> {label}  first={p[0]},{p[1]},{p[2]}  ({secs}s)", flush=True)
                t0 = time.time()
                while time.time() - t0 < secs:
                    d.write_frame(data)
                    time.sleep(0.03)
        except KeyboardInterrupt:
            print("\nhunt stopped", flush=True)
        print("hunt done — which step looked most red?", flush=True)
        return

    if cmd == "color":
        rgb = (255, 255, 255)
        if len(argv) > 1 and not argv[1].startswith("-"):
            rgb = tuple(int(x) for x in argv[1].split(","))
        order = d.channel_order
        use_hdr = d.raw_header
        pixfmt = d.pixel_format
        if "--wire" in argv:
            # Direct wire triple: color --wire 0,0,254  (no channel remap)
            wtriple = argv[argv.index("--wire") + 1]
            b0, b1, b2 = (int(x) for x in wtriple.split(","))
            f = _wire_solid_frame(b0, b1, b2, d.width, d.height, header=use_hdr)
            p = _pix0(f, use_hdr)
            print(
                f"streaming wire-bytes ({b0},{b1},{b2}) wire_px={p} "
                f"header={use_hdr} wire={d.width}x{d.height} "
                f"{'JPEG' if use_jpeg else 'RAW'} (Ctrl-C stop)",
                flush=True,
            )
        else:
            f = _solid_frame(
                rgb, d.width, d.height,
                order=order, header=use_hdr, pixel_format=pixfmt,
            )
            off = 8 if use_hdr else 0
            p = tuple(f[off : off + 3])
            print(
                f"streaming solid RGB{rgb} order={order} fmt={pixfmt} "
                f"wire_px={p} header={use_hdr} wire={d.width}x{d.height} "
                f"{'JPEG' if use_jpeg else 'RAW'} (Ctrl-C stop)",
                flush=True,
            )
        d.ready(jpeg=use_jpeg)
        print(f"frame bytes={len(f)} head16={f[:16].hex()}", flush=True)
        d.stream_bytes(f)
        return

    if cmd == "image":
        path = argv[1]
        hold = float(argv[argv.index("--hold") + 1]) if "--hold" in argv else 30.0
        print(f"showing {path} for {hold}s", flush=True)
        d.ready(jpeg=use_jpeg)
        d.show(Image.open(path), hold=hold)
        return

    if cmd == "stream":
        img = Image.open(argv[1]) if len(argv) > 1 and not argv[1].startswith("-") else _quadrants()
        print(
            f"streaming wire={d.width}x{d.height} "
            f"{'JPEG' if use_jpeg else 'RAW'}, Ctrl-C stop",
            flush=True,
        )
        d.ready(jpeg=use_jpeg)
        d.stream_bytes(d.frame(img))
        return

    if cmd == "quad":
        print(f"streaming quadrants ({'JPEG' if use_jpeg else 'RAW'}), Ctrl-C stop", flush=True)
        d.ready(jpeg=use_jpeg)
        d.stream_bytes(d.frame(_quadrants()))
        return

    print(
        f"test gradient wire={d.width}x{d.height} "
        f"{'JPEG' if use_jpeg else 'RAW'} for 20s",
        flush=True,
    )
    d.ready(jpeg=use_jpeg)
    d.show(_gradient(), hold=20)
    print("done")


if __name__ == "__main__":
    main(sys.argv[1:])
