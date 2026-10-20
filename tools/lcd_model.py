#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Incremental model of the RH-105 LCD controller, fed from an emulator trace.

The emulator's `--lcd-trace=FILE` writes:

    9-byte header "RH105LCD\\1"
    3-byte records: [tag, value_hi, value_lo]
        tag 0 -> command byte written to UIF+0x1A
        tag 1 -> data word written to UIF+0x1C

The controller is S6B33BD-compatible.  Two pixel formats are used by the
firmware, selected by command 0x3A (the low three bits are kept):

    mode 2 -> 8 bits per pixel, packed 3:3:2 (R:G:B).  One trace record per
              pixel, and the 8-bit index addresses the 16-entry red, 16-entry
              green and 16-entry blue banks of the colour table.
    mode 5 -> 16 bits per pixel RGB565.  Two trace records per pixel.

Command 0x2D supplies that 48-byte colour table (16 red, 16 green, 16 blue),
command 0x36 supplies the access-control byte (bit 3 swaps red and blue), and
0x2A / 0x2B define the address window with one start and one end byte each.

The frame is 98x70, which is exactly the window the firmware programs:
0x2A(0x00..0x61) x 0x2B(0x00..0x45) = 6860 pixels, matching the 6860 records
the firmware emits per full redraw.

`LcdModel` decodes records incrementally so a live viewer can poll
`to_rgb()` at any time. `rh105_gui.py` uses this class for the live Tk window;
`write_png()` saves a decoded frame without a display.
"""

import struct
import zlib
from functools import lru_cache
from pathlib import Path

HEADER = b"RH105LCD\1"
LcdError = ValueError


@lru_cache(maxsize=6)
def _pixel_colours(mode, palette, swap):
    colours = []
    for value in range(65536 if mode == 5 else 256):
        if mode == 5:
            colour = ((value >> 11) * 255 // 31,
                      ((value >> 5) & 63) * 255 // 63,
                      (value & 31) * 255 // 31)
        else:
            red, green, blue = value >> 5, (value >> 2) & 7, value & 3
            if palette:
                colour = (palette[0][red] * 255 // 31,
                          palette[1][green] * 255 // 63,
                          palette[2][blue] * 255 // 31)
            else:
                colour = (red * 255 // 7, green * 255 // 7, blue * 255 // 3)
        colours.append(bytes(colour[::-1] if swap else colour))
    return tuple(colours)


def _chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data)))


def write_png(path, model, scale=1):
    """Write the model's framebuffer as a PNG, with no third-party deps.

    Pixels are emitted one per scanline byte (filter type 0), so the result is
    a plain PNG that zlib squeezes into a few kilobytes.
    """
    width, height = model.width * scale, model.height * scale
    rgb = model.to_rgb()
    source_stride = model.width * 3
    rows = bytearray()
    for y in range(model.height):
        row = bytearray()
        start = y * source_stride
        for x in range(model.width):
            row += rgb[start + x * 3:start + x * 3 + 3] * scale
        rows += (b"\0" + row) * scale
    image = b"\x89PNG\r\n\x1a\n"
    image += _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    image += _chunk(b"IDAT", zlib.compress(rows, 9))
    image += _chunk(b"IEND", b"")
    Path(path).write_bytes(image)
    return width, height


def _colour_table(blob):
    """Unpack the 48-byte colour table into 16 red, 16 green and 16 blue levels."""
    if len(blob) != 48:
        raise LcdError("Expected the observed 48-byte colour table")
    return (list(blob[0:16]), list(blob[16:32]), list(blob[32:48]))


class LcdModel:
    """Decode trace records into an RGB888 framebuffer, one window at a time."""

    def __init__(self, width=98, height=70, strict=False, rle=False):
        self.width = width
        self.height = height
        self.strict = strict
        self.rle = rle
        self.pixels = bytearray(width * height * 3)
        self.command: int | None = None
        self.data: list[int] = []
        self.palette = None
        self.mode = 5
        self.access = 0
        self.x0, self.x1, self.y0, self.y1 = 0, width - 1, 0, height - 1
        self.written = 0
        self.commands = 0
        self._pending = b""
        self._index = 0
        self._half = None

    # -- trace intake ----------------------------------------------------
    def feed(self, blob):
        """Consume raw trace bytes.  Returns the number of records decoded.

        A trailing partial record is retained until the next call, so this is
        safe to drive from a live stream; `strict` instead rejects it.
        """
        blob = self._pending + bytes(blob)
        usable = len(blob) - (len(blob) % 3)
        if self.strict and usable != len(blob):
            raise LcdError("Invalid LCD trace record")
        self._pending = blob[usable:]
        # Most pipe reads contain only pixel bytes. Decode those in rows;
        # command records and unusual windows keep the individual-record path.
        records = usable // 3
        if (records and self.command == 0x2C and self.mode in (2, 5) and
                self.x1 < self.width and self.y1 < self.height and
                blob[:usable:3].count(1) == records and
                blob[1:usable:3].count(0) == records):
            self._pixels(blob[2:usable:3])
            return records
        decoded = 0
        for pos in range(0, usable, 3):
            tag = blob[pos]
            value = (blob[pos + 1] << 8) | blob[pos + 2]
            if tag == 0:
                self._record(value)
            elif tag == 1:
                self._value(value)
            else:
                raise LcdError("Invalid LCD trace record")
            decoded += 1
        return decoded

    def feed_file(self, path, chunk_size=1 << 16):
        """Feed a whole trace file, including a leading header if present."""
        with open(path, "rb") as handle:
            head = handle.read(len(HEADER))
            if head != HEADER:
                handle.seek(0)
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    return
                self.feed(chunk)

    # -- decoding --------------------------------------------------------
    def _record(self, command):
        # A new command ends the previous command's data block.
        self._flush()
        self.command = command
        self.data = []
        self.commands += 1
        if command == 0x2C:
            self._index = 0
            self._half = None

    def _value(self, value):
        if value > 255:
            raise LcdError(f"Unsupported LCD data width: {value:#x}")
        if self.command == 0x2C:
            self._pixel(value)
            return
        self.data.append(value)
        # Commands whose operands must be consumed before they take effect.
        if self.command in (0x2A, 0x2B) and len(self.data) in (2, 4):
            self._flush()
        elif self.command in (0x3A, 0x36) and self.data:
            self._flush()
        elif self.command == 0x2D and len(self.data) == 48:
            self._flush()

    def _flush(self):
        """Apply the pending command's operand block."""
        command, data = self.command, self.data
        if not data:
            self.data = []
            return
        self.command, self.data = None, []
        if command in (0x2A, 0x2B):
            if len(data) == 2:
                start, end = data
            elif len(data) == 4:
                start, end = data[0] * 256 + data[1], data[2] * 256 + data[3]
            else:
                raise LcdError("Incomplete LCD address window")
            if not 0 <= start <= end < 256:
                raise LcdError("LCD address window out of bounds")
            if command == 0x2A:
                self.x0, self.x1 = start, end
                self._grow(end + 1, self.height)
            else:
                self.y0, self.y1 = start, end
                self._grow(self.width, end + 1)
        elif command == 0x3A:
            self.mode = data[0] & 7
        elif command == 0x36:
            self.access = data[0]
        elif command == 0x2D:
            self.palette = _colour_table(data)

    def _grow(self, width, height):
        """Match the offline renderer: the panel only ever grows to fit."""
        if width <= self.width and height <= self.height:
            return
        width, height = max(self.width, width), max(self.height, height)
        grown = bytearray(width * height * 3)
        stride = width * 3
        for y in range(self.height):
            grown[y * stride:y * stride + self.width * 3] = \
                self.pixels[y * self.width * 3:(y + 1) * self.width * 3]
        self.pixels, self.width, self.height = grown, width, height

    def _pixel(self, value):
        """Decode one pixel of the current 0x2C block and plot it.

        Pixels are plotted as their bytes arrive rather than batched at the
        end of the block.  A 0x2C block has no terminator, so a trailing frame
        would otherwise never reach the framebuffer -- offline that lost the
        final image, and live it would add a frame of latency.
        """
        if self.mode == 2:
            red, green, blue = value >> 5, (value >> 2) & 7, value & 3
            if self.palette:
                p_red, p_green, p_blue = self.palette
                colour = (p_red[red] * 255 // 31,
                          p_green[green] * 255 // 63,
                          p_blue[blue] * 255 // 31)
            else:
                colour = (red * 255 // 7, green * 255 // 7, blue * 255 // 3)
        elif self.mode == 5:
            if self._half is None:
                self._half = value
                return
            value = (self._half << 8) | value
            self._half = None
            colour = ((value >> 11) * 255 // 31,
                      ((value >> 5) & 63) * 255 // 63,
                      (value & 31) * 255 // 31)
        else:
            raise LcdError(f"Unsupported LCD pixel format {self.mode}")

        index = self._index
        self._index += 1
        area_width = self.x1 - self.x0 + 1
        area_height = self.y1 - self.y0 + 1
        x = self.x0 + index % area_width
        y = self.y0 + (index // area_width) % area_height
        if x >= self.width or y >= self.height:
            return
        swap = bool(self.access & 8)
        offset = (y * self.width + x) * 3
        self.pixels[offset] = colour[2] if swap else colour[0]
        self.pixels[offset + 1] = colour[1]
        self.pixels[offset + 2] = colour[0] if swap else colour[2]
        self.written += 1

    def _pixels(self, data):
        palette = tuple(map(tuple, self.palette)) if self.palette and self.mode == 2 else None
        colours = _pixel_colours(self.mode, palette, bool(self.access & 8))
        if self.mode == 5:
            if self._half is not None:
                data = bytes((self._half,)) + data
            self._half = data[-1] if len(data) & 1 else None
            data = data[:len(data) & ~1]
            rgb = b''.join(colours[value] for value, in struct.iter_unpack('>H', data))
        else:
            rgb = b''.join(colours[value] for value in data)
        count = len(rgb) // 3
        area_width = self.x1 - self.x0 + 1
        area = area_width * (self.y1 - self.y0 + 1)
        position = self._index % area
        consumed = 0
        while consumed < count:
            row, column = divmod(position, area_width)
            run = min(count - consumed, area_width - column)
            offset = ((self.y0 + row) * self.width + self.x0 + column) * 3
            self.pixels[offset:offset + run * 3] = rgb[consumed * 3:(consumed + run) * 3]
            consumed += run
            position = (position + run) % area
        self._index += count
        self.written += count

    # -- output ----------------------------------------------------------
    def to_rgb(self):
        """RGB888 bytes, `width * height * 3`, row major, top-left first."""
        return bytes(self.pixels)

    def scaled_rgb(self, scale=4):
        """Nearest-neighbour upscale, so one pixel stays one flat square."""
        if scale == 1:
            return self.to_rgb()
        row_stride = self.width * 3
        out = bytearray()
        for y in range(self.height):
            row = self.pixels[y * row_stride:(y + 1) * row_stride]
            wide = bytearray()
            for x in range(self.width):
                wide += row[x * 3:x * 3 + 3] * scale
            out += wide * scale
        return bytes(out)

    def ppm(self, scale=4):
        """Binary PPM (P6) of the current frame, for Tk's photo image reader."""
        width, height = self.width * scale, self.height * scale
        return b"P6\n%d %d\n255\n" % (width, height) + self.scaled_rgb(scale)

    def stats(self):
        return {"width": self.width, "height": self.height, "mode": self.mode,
                "palette": self.palette is not None, "access": self.access,
                "commands": self.commands, "pixels": self.written}
