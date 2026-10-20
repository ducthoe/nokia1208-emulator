#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""CSTN pixel response and window optics for the RH-105 handset photograph.

Panel response is integrated at native resolution in wall time. The response
constants and optical curves are estimates, not measurements of a 1208 panel.
"""

from __future__ import annotations

import math
import time

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageMath, ImageStat


# Estimated optical time constants; 10–90% transitions take about 2.2 times tau.
BRIGHTEN_TAU = 0.035
DARKEN_TAU = 0.055
SETTLE_NS = round(8 * max(BRIGHTEN_TAU, DARKEN_TAU) * 1_000_000_000)


def _curve(black: int, gain: float, gamma: float = 1.0):
    """Per-channel display curve: black lift, reduced contrast, gamma."""
    table = []
    for value in range(256):
        out = black + gain * 255.0 * (value / 255.0) ** gamma
        table.append(max(0, min(255, round(out))))
    return table


def _radial(size, power=1.0):
    """White centre falling to black at the corners."""
    width, height = size
    grad = Image.radial_gradient('L').resize((width, height), Image.BILINEAR)
    grad = grad.point(lambda value: 255 - value)
    if power != 1.0:
        grad = grad.point(lambda value: round(255 * (value / 255.0) ** power))
    return grad


class LcdShader:
    """Render an RGB888 98x70 framebuffer like the 1208's CSTN window."""

    def __init__(self, width: int, height: int, columns: int = 98, rows: int = 70,
                 *, glass: Image.Image | None = None):
        self.width, self.height = width, height
        self.columns, self.rows = columns, rows
        self._grid = self._make_grid()
        self._backlight = self._make_backlight()
        self._reflection = self._make_reflection(glass)
        self._red_curve = _curve(18, 0.78, 0.98)
        self._green_curve = _curve(22, 0.80, 0.98)
        self._blue_curve = _curve(30, 0.82, 0.98)
        self._bezel = self._make_bezel()
        self.reset()

    def reset(self):
        self._rgb = None
        self._target = self._cells = None
        self._updated_ns = self._changed_ns = 0
        self.settling = False

    def _advance(self, now_ns):
        elapsed = max(0, now_ns - self._updated_ns) / 1_000_000_000
        self._updated_ns = now_ns
        if not self.settling or elapsed == 0:
            return
        if now_ns - self._changed_ns >= SETTLE_NS:
            self._cells = self._target
            self.settling = False
            return
        brighten = -math.expm1(-elapsed / BRIGHTEN_TAU)
        darken = -math.expm1(-elapsed / DARKEN_TAU)
        # Floating-point cells let small residuals decay instead of sticking
        # at the last few integer levels. Each pixel chooses its own direction.
        self._cells = tuple(ImageMath.lambda_eval(
            lambda p: p['old'] + (p['target'] - p['old']) * (
                darken + (brighten - darken) * (p['target'] > p['old'])),
            old=old, target=target) for old, target in zip(self._cells, self._target))

    # -- static optical layers ------------------------------------------
    def _make_grid(self):
        """Black matrix between cells plus the passive row electrodes.

        Drawn supersampled so the 2.4-pixel period does not turn into a
        staircase, then multiplied over the image.  255 means clear.
        """
        width, height = self.width, self.height
        ss = 4
        big = Image.new('L', (width * ss, height * ss), 255)
        draw = ImageDraw.Draw(big)
        column_dark = round(255 * 0.90)
        row_dark = round(255 * 0.93)
        for column in range(1, self.columns):
            x = round(column * big.width / self.columns)
            draw.line([(x, 0), (x, big.height)], fill=column_dark, width=ss)
        for row in range(1, self.rows):
            y = round(row * big.height / self.rows)
            draw.line([(0, y), (big.width, y)], fill=row_dark, width=ss)
        big = big.resize((width, height), Image.LANCZOS)
        # Edge falloff: the window is recessed behind a raised frame.
        vignette = _radial((width, height), 1.6).point(
            lambda value: round(255 - (255 - value) * 0.22))
        big = ImageChops.multiply(big, vignette)
        return big.convert('RGB')

    def _make_bezel(self):
        """A soft inner shadow where the panel meets its black frame."""
        width, height = self.width, self.height
        shadow = Image.new('L', (width, height), 0)
        draw = ImageDraw.Draw(shadow)
        draw.rectangle([3, 3, width - 4, height - 4], fill=255)
        shadow = shadow.filter(ImageFilter.GaussianBlur(1.8))
        shadow = shadow.point(lambda value: round(150 + value * 0.41))
        return shadow.convert('RGB')

    def _make_backlight(self):
        """Cool LED bleed, strongest in the middle and a little top-heavy."""
        width, height = self.width, self.height
        radial = _radial((width, height), 1.4)
        # Gentle top bias: light pipe at the top edge of the module.
        top = Image.linear_gradient('L').resize((width, height), Image.BILINEAR)
        top = top.point(lambda value: round(255 - value * 0.30))
        mask = ImageChops.multiply(radial, top)
        mask = mask.point(lambda value: round(6 + value / 255.0 * 13))
        red = mask.point(lambda value: round(value * 0.70))
        green = mask.point(lambda value: round(value * 0.82))
        blue = mask.point(lambda value: round(value * 1.00))
        return Image.merge('RGB', (red, green, blue))

    def _make_reflection(self, glass):
        """Retain the light reflected in the actual handset photograph."""
        if glass is None:
            return Image.new('RGB', (self.width, self.height))
        glass = glass.convert('RGB')
        # Remove the unlit panel's base tint and soften its photographed cell
        # grid, leaving the location and color of the reflected light intact.
        floor = tuple(ImageStat.Stat(glass).median)
        radius = max(1.0, glass.width / self.columns * 0.7)
        light = glass.filter(ImageFilter.GaussianBlur(radius))
        light = ImageChops.subtract(light, Image.new('RGB', glass.size, floor))
        light = light.point(lambda value: round(value * 0.55))
        return light.resize((self.width, self.height), Image.LANCZOS)

    # -- per-frame pipeline ---------------------------------------------
    def render(self, rgb: bytes | None = None, *, now_ns: int | None = None,
               frame_ns: int | None = None) -> Image.Image:
        """Latch a new framebuffer, or keep settling the current one."""
        if now_ns is None:
            now_ns = time.monotonic_ns()
        if rgb is not None and rgb != self._rgb:
            received_ns = now_ns if frame_ns is None else min(now_ns, frame_ns)
            received_ns = max(self._updated_ns, received_ns)
            self._advance(received_ns)
            source = Image.frombytes('RGB', (self.columns, self.rows), rgb)
            grey = source.convert('L').convert('RGB')
            red, green, blue = Image.blend(grey, source, 0.56).split()
            self._target = tuple(channel.point(curve).convert('F') for channel, curve in (
                (red, self._red_curve), (green, self._green_curve),
                (blue, self._blue_curve)))
            self._rgb = rgb
            self._changed_ns = received_ns
            if self._cells is None:
                self._cells = self._target
            else:
                self.settling = True
        self._advance(now_ns)
        if self._cells is None:
            raise ValueError('the first render needs a framebuffer')
        image = Image.merge('RGB', tuple(channel.convert('L') for channel in self._cells))
        image = image.resize((self.width, self.height), Image.NEAREST)
        # A small cell-edge spread models the window without washing out text.
        pixel_pitch = min(self.width / self.columns, self.height / self.rows)
        image = image.filter(ImageFilter.GaussianBlur(0.18 * pixel_pitch))

        image = ImageChops.add(image, self._backlight)

        # Backlight bloom around white areas. Blurring at quarter scale then
        # upsampling costs a fraction of the full-resolution blur and the glow
        # is too soft to show the difference.
        lum = image.convert('L')
        bright = lum.point(lambda value: 0 if value < 118 else round((value - 118) * 0.55))
        radius = max(1.4, self.width * 0.014)
        small = (max(1, self.width // 4), max(1, self.height // 4))
        bloom = bright.resize(small, Image.BILINEAR).filter(
            ImageFilter.GaussianBlur(radius / 4)).resize(
                (self.width, self.height), Image.BILINEAR)
        image = ImageChops.add(image, Image.merge('RGB', (bloom, bloom, bloom)))

        # Cell gaps and row electrodes.
        image = ImageChops.multiply(image, self._grid)

        # The plastic window sits on top of the panel.
        image = ImageChops.screen(image, self._reflection)
        return ImageChops.multiply(image, self._bezel)
