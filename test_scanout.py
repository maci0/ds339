#!/usr/bin/env python3
"""Verify host scanout: white vs black must differ; solids must not be logo-only."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image

from ds339 import DS339, _solid_frame

OUT = Path("capture/scanout")
OUT.mkdir(parents=True, exist_ok=True)


def grab(path: Path) -> bool:
    subprocess.run(
        [
            "ffmpeg", "-y", "-f", "v4l2", "-input_format", "mjpeg",
            "-video_size", "1280x720", "-i", "/dev/video0",
            "-frames:v", "1", "-q:v", "3", str(path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=8,
    )
    return path.exists() and path.stat().st_size > 2000


def measure(path: Path) -> tuple[np.ndarray, float, float]:
    a = np.asarray(Image.open(path).convert("RGB"))
    h, w = a.shape[:2]
    crop = a[int(h * 0.45) : int(h * 0.72), int(w * 0.10) : int(w * 0.40)]
    Image.fromarray(crop).resize((400, 300)).save(
        path.with_name(path.stem + "_t.jpg"), quality=90
    )
    mean = crop.mean(axis=(0, 1))
    bright = float((crop.max(axis=2) > 50).mean())
    std = float(crop.reshape(-1, 3).std())
    return mean, bright, std


def stream(d: DS339, rgb: tuple[int, int, int], secs: float = 2.5) -> None:
    f = _solid_frame(rgb, d.width, d.height, order="bgr", header=True)
    t_end = time.time() + secs
    n = 0
    while time.time() < t_end:
        d.write_frame(f)
        n += 1
        time.sleep(0.02)
    print(f"  streamed {n} frames RGB{rgb}", flush=True)


def main() -> int:
    d = DS339()
    print(
        f"product={d.product:#06x} screen={d.screen_reg:#06x} "
        f"wire={d.width}x{d.height} mode={d.mode}",
        flush=True,
    )
    t0 = time.time()
    d.ready(jpeg=False)
    print(
        f"ready {time.time() - t0:.2f}s "
        f"F004={d.reg_read(0xF004):#04x} F037={d.reg_read(0xF037):#04x} "
        f"F7E9={d.reg_read(0xF7E9):#04x} F242={d.reg_read(0xF242):#04x}",
        flush=True,
    )

    results: dict[str, tuple] = {}
    for name, rgb in (
        ("WHT", (255, 255, 255)),
        ("BLK", (0, 0, 0)),
        ("RED", (255, 0, 0)),
        ("GRN", (0, 255, 0)),
        ("BLU", (0, 0, 255)),
    ):
        print(f">>> {name}", flush=True)
        t0 = time.time()
        f = _solid_frame(rgb, d.width, d.height, order="bgr", header=True)
        d.write_frame(f)
        print(
            f"  first {time.time() - t0:.2f}s armed={d._armed_video} "
            f"F004={d.reg_read(0xF004):#04x}",
            flush=True,
        )
        stream(d, rgb, 2.2)
        path = OUT / f"{name}.jpg"
        if grab(path):
            results[name] = measure(path)
            m, b, s = results[name]
            print(
                f"  mean={m.round(0).astype(int).tolist()} bright={b:.3f} std={s:.1f}",
                flush=True,
            )
        else:
            print("  grab failed", flush=True)

    if "WHT" in results and "BLK" in results:
        delta = results["WHT"][0] - results["BLK"][0]
        print(f"WHT-BLK delta={delta.round(0).astype(int).tolist()}", flush=True)
        # Host content is on if white is clearly brighter than black
        if float(delta.mean()) > 25:
            print("PASS: host scanout looks live (white >> black)", flush=True)
            return 0
        print("FAIL: white≈black — still logo/OSD or black host buffer", flush=True)
        return 2
    print("FAIL: missing captures", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
