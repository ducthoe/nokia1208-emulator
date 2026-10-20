#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Live LCD, keypad and phone audio for the RH-105 development emulator.

Run: python3 tools/rh105_gui.py [--scale=4] [--tone=500]
F1/F2 are softkeys; arrows and Return navigate; F3 calls; F4 ends/powers.
Digits, * and # work directly. Audio includes firmware PCM and the UEM buzzer.
"""

import argparse
import fcntl
import hashlib
import io
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from collections import deque
from pathlib import Path
from tkinter import filedialog, ttk

try:
    from PIL import Image, ImageChops, ImageDraw, ImageFilter
except ImportError:  # The emulator still runs without the photographic skin.
    Image = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lcd_model import HEADER, LcdModel, write_png

try:
    from lcd_shader import LcdShader
except ImportError:
    LcdShader = None

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'build/rh105'
FLASH = ROOT / 'build/rh105-eo/flash.bin'
RAW_FLASH = ROOT / 'build/rh105-eo/raw-flash.bin'
TDS6 = ROOT / 'firmware/TDS6.BIN'
NVRAM = ROOT / 'assets/rh105_factory_nvram.bin'
STORAGE = ROOT / 'state/nvram.bin'
LCD_WIDTH, LCD_HEIGHT = 98, 70
PCM_RATE = 44100
# ALSA owns the output clock; firmware samples retain their original rate.
AUDIO_PERIOD_MS = 10
AUDIO_PERIOD_BYTES = PCM_RATE * AUDIO_PERIOD_MS // 1000 * 2
AUDIO_RING_BYTES = AUDIO_PERIOD_BYTES * 6  # 60 ms cushion, then drop the oldest
PCM_PIPE_BYTES = 4096
PAINT_INTERVAL_NS = 16_666_667


PCM_READ = 1 << 16
PLAYER_RESTART_DELAY = 2.0
F_SETPIPE_SZ = getattr(fcntl, 'F_SETPIPE_SZ', 1031)
F_GETPIPE_SZ = getattr(fcntl, 'F_GETPIPE_SZ', 1032)


def shrink_pipe(fd, size):
    """Cap a pipe's capacity; keep the default when the kernel refuses."""
    try:
        fcntl.fcntl(fd, F_SETPIPE_SZ, size)
    except OSError:
        pass


def stale_build():
    """Name the source newer than build/rh105, if any.

    A stale runner rejects flags it predates with misleading errors (a new
    --nvram= option, for example, falls through to the numeric instruction
    limit parser), so the GUI warns instead of looking as if its own args failed.
    """
    try:
        built = BINARY.stat().st_mtime
    except OSError:
        return None
    newest, name = built, ''
    for source in [ROOT / 'Makefile', *(ROOT / 'src').glob('*.c'),
                   *(ROOT / 'src').glob('*.h')]:
        try:
            mtime = source.stat().st_mtime
        except OSError:
            continue
        if mtime > newest:
            newest, name = mtime, source.name
    return name or None

# Index = E row * 4 + D column. Translation: 0x01238c20; scanner: 0x011f2716.
# UI roles are verified by the key rules at 0x012125d4 and guest LCD output.
# This handset has no separate centre switch: the convenient OK button and
# Return are aliases for the left softkey (Select). Matrix position 2 is unused.
KEYPAD = [
    [('Left soft', 7), None, ('Right soft', 10)],
    [None, ('Up', 5), None],
    [('Left', 19), ('OK', 7), ('Right', 16)],
    [None, ('Down', 6), None],
    [('Call', 18), None, ('End', 20)],
    [('1', 0), ('2', 12), ('3', 8)],
    [('4', 1), ('5', 13), ('6', 9)],
    [('7', 17), ('8', 14), ('9', 4)],
    [('*', 3), ('0', 15), ('#', 11)],
]
KEY_INDEX = dict(cell for row in KEYPAD for cell in row if cell)
KEY_BINDINGS = {label: index for label, index in KEY_INDEX.items() if len(label) == 1}
KEY_BINDINGS.update({keysym: KEY_INDEX[label] for keysym, label in {
    'F1': 'Left soft', 'F2': 'Right soft', 'F3': 'Call', 'F4': 'End',
    'Up': 'Up', 'Down': 'Down', 'Left': 'Left', 'Right': 'Right',
    'Return': 'OK', 'KP_Enter': 'OK', 'asterisk': '*', 'numbersign': '#',
    'multiply': '*',
}.items()})
for _digit in range(10):
    KEY_BINDINGS[f'KP_{_digit}'] = KEY_BINDINGS[str(_digit)]


class KeypadInput:
    """Merge mouse/keyboard owners without duplicate presses or stuck keys."""

    def __init__(self, send):
        self.send = send
        self.owners = {}

    def press(self, source, index):
        if source in self.owners:
            return
        held = index in self.owners.values()
        self.owners[source] = index
        if not held:
            self.send(index, 1)

    def release(self, source):
        index = self.owners.pop(source, None)
        if index is not None and index not in self.owners.values():
            self.send(index, 0)

    def release_all(self):
        for index in set(self.owners.values()):
            self.send(index, 0)
        self.owners.clear()


class LogBuffer:
    def __init__(self, limit=2000):
        self._lines = deque(maxlen=limit)
        self._lock = threading.Lock()
        self.revision = 0

    def __call__(self, line):
        with self._lock:
            self._lines.append(line)
            self.revision += 1
        if os.environ.get('RH105_VERBOSE') == '1':
            print(f'[rh105] {line}', file=sys.stderr)

    def snapshot(self):
        with self._lock:
            return self.revision, '\n'.join(self._lines)


def terminate(process):
    """Reap our process group, including a player which ignores SIGTERM."""
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    process.wait()


class Emulator:
    """Own one isolated run. A single cancellable worker drains all output.

    FIFO endpoints are opened nonblocking before spawning, so early startup
    failure cannot strand a reader in open(). Audio writes are nonblocking,
    atomic pipe-sized chunks: a slow/unavailable player cannot stall firmware.
    Every audio buffer is capped and holds only the newest samples, so playback
    stays close to the emulated clock instead of drifting a whole session behind.
    """

    def __init__(self, scale, instruction_limit, tone, log, realtime=True, sim=True):
        self.scale, self.instruction_limit, self.tone = scale, instruction_limit, tone
        self.realtime = realtime
        self.sim = sim
        self.log = log
        self.process = None
        self.player = None
        self.lock = threading.Lock()
        self.lcd = LcdModel(LCD_WIDTH, LCD_HEIGHT)
        self.lcd_updated_ns = time.monotonic_ns()
        self.dirty = True
        self.keys = 0
        self.stop_reason = ''
        self.audio_error = ''
        self.audio_dropped_bytes = 0
        self.audio_received_bytes = 0
        self._audio_ring = bytearray()
        self._audio_lock = threading.Lock()
        self._audio_ready = threading.Event()
        self._writer = None
        self._tempdir = None
        self._thread = None
        self._stop = threading.Event()
        self._fds = []

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self):
        self.stop()
        for path in (BINARY, FLASH, RAW_FLASH, TDS6, NVRAM):
            if not path.is_file():
                self.log(f'[gui] missing {path}; run make and prepare the development profile')
                self.stop_reason = 'missing input'
                return False
        stale = stale_build()
        if stale:
            self.log(f'[gui] build/rh105 is older than src/{stale}; run make, '
                     'a stale runner misreads newer emulator flags')
        self._stop = threading.Event()
        self.lcd = LcdModel(LCD_WIDTH, LCD_HEIGHT)
        self.lcd_updated_ns = time.monotonic_ns()
        self.dirty, self.keys = True, 0
        self.stop_reason, self.audio_error = '', ''
        self.audio_dropped_bytes = 0
        self.audio_received_bytes = 0
        with self._audio_lock:
            self._audio_ring.clear()
            self._audio_ready.clear()
        try:
            STORAGE.parent.mkdir(parents=True, exist_ok=True)
            self._tempdir = tempfile.TemporaryDirectory(prefix='rh105-gui-')
            paths = [Path(self._tempdir.name) / name for name in ('lcd', 'pcm')]
            for path in paths:
                os.mkfifo(path)
                self._fds.append(os.open(path, os.O_RDWR | os.O_NONBLOCK))
            command = [str(BINARY), str(FLASH), str(self.instruction_limit),
                       f'--raw-flash={RAW_FLASH}', '--legacy-reset-state', '--rom-hle',
                       f'--tds6-safer={TDS6}', '--virtual-imei=000000000000000',
                       f'--nvram-seed={NVRAM}',
                       f'--nvram={STORAGE}',
                       '--mdi-peer', '--stdin-keys', '--no-history',
                       f'--lcd-trace={paths[0]}']
            command.extend(['--sim-detect-high', '--virtual-sim'] if self.sim
                           else ['--no-sim'])
            if self.realtime:
                command.append('--realtime')
            env = dict(os.environ, RH105_PCM=str(paths[1]))
            if self.tone is not None:
                env['RH105_BUZZER_TEST'] = str(self.tone)
            self.process = subprocess.Popen(command, cwd=ROOT, env=env,
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, start_new_session=True)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.player = self._spawn_player()
            self.log('$ ' + ' '.join(command))
            self._thread = threading.Thread(target=self._read_output,
                                           args=(self.process, tuple(self._fds), self.player),
                                           name='rh105-output', daemon=True)
            self._thread.start()
            self._writer = threading.Thread(target=self._audio_writer,
                                           name='rh105-audio', daemon=True)
            self._writer.start()
            return True
        except OSError as error:
            self.log(f'[gui] startup failed: {error}')
            self.stop()
            self.stop_reason = 'startup failed'
            return False

    def stop(self):
        self._stop.set()
        self._audio_ready.set()
        terminate(self.process)
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise RuntimeError('emulator output worker did not stop')
            self._thread = None
        if self._writer is not None:
            self._writer.join(timeout=1)
            if self._writer.is_alive():
                raise RuntimeError('emulator audio worker did not stop')
            self._writer = None
        terminate(self.player)
        for process in (self.process, self.player):
            if process:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream:
                        stream.close()
        self.process = self.player = None
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()
        if self._tempdir:
            self._tempdir.cleanup()
            self._tempdir = None

    def key(self, index, state):
        if not 0 <= index <= 20 or state not in (0, 1, 2):
            raise ValueError('invalid keypad command')
        if not self.running:
            return False
        try:
            if 'RH105_LCD_TIMING' in os.environ:
                self.log(f'[timing] host-key={index} state={state} '
                         f'wall_ns={time.monotonic_ns()}')
            os.write(self.process.stdin.fileno(), f'{index} {state}\n'.encode('ascii'))
            self.keys += 1
            return True
        except (OSError, ValueError) as error:
            self.log(f'[gui] input failed: {error}')
            # Do not silently lose a release and leave a key held indefinitely.
            terminate(self.process)
            self.stop_reason = 'input pipe failed'
            return False

    def _line(self, data):
        line = data.decode('utf-8', errors='replace')
        if line.startswith('Cannot lock handset storage '):
            self.stop_reason = 'Saved phone is already open in another emulator'
        reason = re.search(r'"stop_reason"\s*:\s*"([^"\\]*)"', line)
        if reason:
            self.stop_reason = reason.group(1)
        self.log(line)

    def _spawn_player(self):
        """Start the sink with buffers small enough to keep latency predictable."""
        aplay = shutil.which('aplay')
        if not aplay:
            self.audio_error = 'aplay not found'
            return None
        try:
            player = subprocess.Popen(
                [aplay, '-q', '-t', 'raw', '-f', 'S16_LE', '-r', str(PCM_RATE), '-c', '1',
                 '--buffer-time=40000', '--period-time=10000', '--start-delay=10000', '-'],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError as error:
            self.audio_error = str(error)
            return None
        os.set_blocking(player.stdin.fileno(), False)
        # A default 64 KiB pipe holds 743 ms of audio that the sink never gives
        # back; cap it so queued audio cannot outlive the moment it was played.
        shrink_pipe(player.stdin.fileno(), PCM_PIPE_BYTES)
        self.audio_error = ''
        return player

    def _queue_pcm(self, chunk):
        """Hold produced audio, keeping only the newest AUDIO_RING_BYTES."""
        self.audio_received_bytes += len(chunk)
        with self._audio_lock:
            ring = self._audio_ring
            ring += chunk
            excess = len(ring) - AUDIO_RING_BYTES
            if excess > 0:
                dropped = min(excess + (excess & 1), len(ring))
                del ring[:dropped]
                self.audio_dropped_bytes += dropped
            self._audio_ready.set()

    def _audio_writer(self):
        """Pass PCM periods unchanged; the audio device paces writes."""
        report_at, report_rx = time.monotonic(), 0
        while not self._stop.is_set():
            player = self.player
            if player is None or player.poll() is not None:
                self._stop.wait(0.05)
                continue
            with self._audio_lock:
                if len(self._audio_ring) < AUDIO_PERIOD_BYTES:
                    block = None
                    self._audio_ready.clear()
                else:
                    block = bytes(self._audio_ring[:AUDIO_PERIOD_BYTES])
                    del self._audio_ring[:AUDIO_PERIOD_BYTES]
            if block is None:
                self._audio_ready.wait(0.02)
                continue
            offset = 0
            while offset < len(block) and not self._stop.is_set():
                if player is not self.player or player.poll() is not None:
                    break
                try:
                    offset += os.write(player.stdin.fileno(), block[offset:])
                except BlockingIOError:
                    try:
                        select.select([], [player.stdin.fileno()], [], 0.02)
                    except (OSError, ValueError):
                        break
                except (OSError, ValueError):
                    break
            self.audio_dropped_bytes += len(block) - offset
            now = time.monotonic()
            if now - report_at >= 5.0:
                self._report_audio(now - report_at, report_rx)
                report_at, report_rx = now, self.audio_received_bytes

    def _report_audio(self, elapsed, received_before):
        """Log how much of realtime the emulator delivered, every few seconds."""
        frames = (self.audio_received_bytes - received_before) / 2 / elapsed
        self.log(f'[gui] audio {frames:.0f} Hz ({frames / PCM_RATE * 100:.0f}% of '
                 f'{PCM_RATE}), fixed {PCM_RATE} Hz output, dropped {self.audio_dropped_bytes} B')

    def _player_exited(self, player, errors):
        lines = errors.decode(errors='replace').strip().splitlines()
        tail = lines[-1] if lines else ''
        if tail:
            self.audio_error = tail
        self.log(f'[gui] audio player exited {player.returncode}'
                 + (f' ({tail})' if tail else '') + '; restarting')
        for stream in (player.stdin, player.stdout, player.stderr):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass

    def _read_output(self, process, fds, player):
        lcd_fd, pcm_fd = fds
        output_fd = process.stdout.fileno()
        readers = {lcd_fd, pcm_fd, output_fd}
        player_fd = player.stderr.fileno() if player else None
        if player_fd is not None:
            readers.add(player_fd)
        header, output, errors = bytearray(), bytearray(), bytearray()
        pcm_tail = b''
        respawn_at = 0.0
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select(list(readers), [], [], 0.05)
                if not ready and process.poll() is not None:
                    break
                for fd in sorted(ready, key=lambda item: item != pcm_fd):
                    chunk = os.read(fd, PCM_READ if fd == pcm_fd else 4096)
                    if not chunk:
                        readers.discard(fd)
                        continue
                    if fd == lcd_fd:
                        if len(header) < len(HEADER):
                            needed = len(HEADER) - len(header)
                            header.extend(chunk[:needed])
                            chunk = chunk[needed:]
                            if len(header) == len(HEADER) and header != HEADER:
                                raise ValueError('unexpected LCD trace header')
                        if chunk:
                            with self.lock:
                                self.lcd.feed(chunk)
                                self.lcd_updated_ns = time.monotonic_ns()
                                self.dirty = True
                    elif fd == pcm_fd:
                        chunk = pcm_tail + chunk
                        pcm_tail = chunk[len(chunk) & ~1:]
                        self._queue_pcm(chunk[:len(chunk) & ~1])
                    elif fd == player_fd:
                        errors.extend(chunk)
                        del errors[:-2048]
                    else:
                        output.extend(chunk)
                        while b'\n' in output:
                            line, _, output = output.partition(b'\n')
                            self._line(line)
                        if len(output) > 65536:
                            self._line(output[:65536])
                            del output[:65536]
                if player is not None and player.poll() is not None:
                    self._player_exited(player, errors)
                    errors = bytearray()
                    readers.discard(player_fd)
                    player, player_fd = None, None
                    with self._audio_lock:
                        self._audio_ring.clear()
                    respawn_at = time.monotonic() + PLAYER_RESTART_DELAY
                elif player is None and respawn_at and time.monotonic() >= respawn_at:
                    if self._stop.is_set():
                        break
                    player = self._spawn_player()
                    if player is None:
                        respawn_at = time.monotonic() + PLAYER_RESTART_DELAY
                    else:
                        player_fd = player.stderr.fileno()
                        readers.add(player_fd)
                        respawn_at = 0.0
                        self.player = player
                        self.log('[gui] audio player restarted')
            if output:
                self._line(output)
            if process.poll() is not None:
                self.log(f'[gui] emulator exited {process.returncode}')
                if not self.stop_reason:
                    self.stop_reason = f'exit {process.returncode}'
        except (OSError, ValueError) as error:
            self.log(f'[gui] output failed: {error}')
            self.stop_reason = 'output failed'
            terminate(process)
        finally:
            terminate(player)


# --------------------------------------------------------------------------
# Visual language
# --------------------------------------------------------------------------
BG = '#0b0d10'
LINE = '#1d2229'
TEXT = '#eef1f5'
DIM = '#7d8590'
FAINT = '#4c535d'
GREEN = '#8ac7a0'
RED = '#d29393'
BTN_BG = '#14181e'
BTN_HOVER = '#1b2129'
BTN_LINE = '#272d36'
SANS = 'DejaVu Sans'
MONO = 'DejaVu Sans Mono'

UI_W, UI_H = 880, 900
LEFT_W = 550
PHONE_H = 780
PHONE_TOP = 54
CHASSIS = ROOT / 'assets/nokia1208_chassis.png'

# Chassis-native key outlines (the 359x824 crop of the Pixabay handset).
# The active LCD is exactly 239x171 px there: 98:70.
SCREEN = (67, 183, 306, 354)
KEYS = (
    ('Left soft', 7, ((39, 453), (130, 453), (120, 467), (115, 487), (115, 507), (39, 507))),
    ('Right soft', 10, ((235, 453), (327, 453), (327, 507), (248, 507), (247, 487), (242, 467))),
    ('Call', 18, ((39, 512), (115, 512), (120, 540), (134, 561), (39, 561))),
    ('End', 20, ((248, 512), (327, 512), (326, 561), (231, 561), (244, 540))),
    ('Up', 5, ((126, 473), (144, 461), (216, 461), (233, 473), (220, 493),
               (207, 480), (157, 480), (145, 493))),
    ('Left', 19, ((126, 473), (145, 493), (145, 525), (158, 537), (141, 553),
                  (125, 541), (119, 527), (119, 492))),
    ('OK', 7, ((157, 480), (207, 480), (220, 493), (220, 525), (208, 537),
               (158, 537), (145, 525), (145, 493))),
    ('Right', 16, ((233, 473), (241, 489), (244, 526), (237, 541), (219, 554),
                   (208, 537), (220, 525), (220, 493))),
    ('Down', 6, ((141, 553), (158, 537), (208, 537), (219, 554), (205, 557), (156, 557))),
    ('1', 0, ((40, 571), (135, 574), (135, 620), (44, 618))),
    ('2', 12, ((141, 574), (231, 574), (231, 620), (141, 620))),
    ('3', 8, ((237, 574), (327, 570), (324, 618), (237, 620))),
    ('4', 1, ((44, 628), (135, 631), (135, 676), (46, 674))),
    ('5', 13, ((141, 631), (228, 631), (228, 677), (141, 677))),
    ('6', 9, ((234, 631), (323, 628), (321, 674), (234, 677))),
    ('7', 17, ((47, 684), (135, 688), (135, 732), (51, 728))),
    ('8', 14, ((141, 689), (227, 689), (227, 733), (141, 733))),
    ('9', 4, ((233, 688), (320, 684), (315, 728), (233, 732))),
    ('*', 3, ((53, 741), (135, 746), (135, 785), (78, 779), (62, 765))),
    ('0', 15, ((141, 747), (226, 747), (226, 786), (141, 786))),
    ('#', 11, ((232, 746), (313, 739), (307, 764), (291, 779), (232, 785))),
)


def rounded(canvas, x0, y0, x1, y1, radius, **options):
    """A smooth polygon approximation of a rounded rectangle."""
    points = (
        x0 + radius, y0, x1 - radius, y0, x1, y0,
        x1, y0 + radius, x1, y1 - radius, x1, y1,
        x1 - radius, y1, x0 + radius, y1, x0, y1,
        x0, y1 - radius, x0, y0 + radius, x0, y0,
    )
    return canvas.create_polygon(points, smooth=True, **options)


class PillButton(tk.Canvas):
    """Flat, quiet button used by the side panel."""

    def __init__(self, master, text, command, width=270, height=36, danger=False):
        super().__init__(master, width=width, height=height, bg=BG,
                         highlightthickness=0, bd=0, cursor='hand2')
        self._btn_w, self._btn_h = width, height
        self.text, self.command, self.danger = text, command, danger
        self._hover = self._pressed = False
        self._draw()
        self.bind('<Enter>', self._enter)
        self.bind('<Leave>', self._leave)
        self.bind('<ButtonPress-1>', self._press)
        self.bind('<ButtonRelease-1>', self._release)

    def _draw(self):
        self.delete('all')
        hovered = self._hover or self._pressed
        rounded(self, 1, 1, self._btn_w - 1, self._btn_h - 1, 9,
                fill=BTN_HOVER if hovered else BTN_BG,
                outline='#3b4552' if hovered else BTN_LINE, width=1)
        colour = '#d8a6a6' if self.danger else TEXT
        self.create_text(15, self._btn_h / 2, text=self.text, anchor='w',
                         fill=colour, font=(SANS, 10))
        self.create_text(self._btn_w - 15, self._btn_h / 2, text='›', anchor='e',
                         fill=DIM if not self.danger else '#9c7070', font=(SANS, 14))

    def _enter(self, _event):
        self._hover = True
        self._draw()

    def _leave(self, _event):
        self._hover = False
        self._draw()

    def _press(self, _event):
        self._pressed = True
        self._draw()

    def _release(self, event):
        self._pressed = False
        self._draw()
        if 0 <= event.x < self._btn_w and 0 <= event.y < self._btn_h:
            self.command()


class Rh105Gui:
    """The handset photograph, its lit CSTN window and the side panel."""

    def __init__(self, root, emulator, scale=1):
        if scale <= 0:
            raise ValueError('scale must be positive')
        self.root, self.emulator = root, emulator
        self.scale = scale
        self.input = KeypadInput(emulator.key)
        self._callbacks, self._releases = set(), {}
        self._closed = False
        self._screen_photo = self._scene_base = self._screen_pil = None
        self._screen_rgb = b'\0' * (LCD_WIDTH * LCD_HEIGHT * 3)
        self._shader = None
        self.shader_enabled = tk.BooleanVar(master=root, value=True)
        self._hover_label = None
        self._held = frozenset()
        self._drawn_hover = object()
        self._status_text = self._detail_text = ''
        self._log_window = self._log_text = None
        self._log_revision = -1
        self._trace_lcd_timing = 'RH105_LCD_TIMING' in os.environ
        self.hotspots = {}
        self.key_shapes = {}
        self._hover_items = {}
        self._press_items = {}

        root.title('Nokia 1208 (RH-105)')
        root.configure(bg=BG)
        root.geometry(f'{UI_W}x{UI_H}')
        root.resizable(False, False)
        root.protocol('WM_DELETE_WINDOW', self.close)

        self._build_scene()
        self._build_canvas()
        self._build_panel()

        root.bind('<KeyPress>', self._key_press)
        root.bind('<KeyRelease>', self._key_release)
        root.bind('<FocusOut>', self._focus_out)
        root.bind('<Unmap>', lambda event: self._release_all() if event.widget == root else None)
        self._painted_ns = 0
        self._paint_screen(b'\0' * (LCD_WIDTH * LCD_HEIGHT * 3))
        self._after(16, self._refresh)

    # -- composition -----------------------------------------------------
    @staticmethod
    def _photo(image, alpha=False):
        if alpha:
            buffer = io.BytesIO()
            image.save(buffer, 'PNG')
            return tk.PhotoImage(data=buffer.getvalue())
        image = image.convert('RGB')
        header = b'P6\n%d %d\n255\n' % image.size
        return tk.PhotoImage(data=header + image.tobytes(), format='PPM')

    def _build_scene(self):
        if Image is None or not CHASSIS.is_file():
            return
        source = Image.open(CHASSIS).convert('RGBA')
        photo_h = max(1, min(round(PHONE_H * self.scale), UI_H - PHONE_TOP))
        scale = photo_h / source.height
        width = round(source.width * scale)
        phone = source.resize((width, photo_h), Image.LANCZOS)
        phone_x = (LEFT_W - width) // 2

        bg = Image.new('RGB', (LEFT_W, UI_H))
        top, bottom = (10, 12, 15), (19, 22, 27)
        draw = ImageDraw.Draw(bg)
        for y in range(UI_H):
            mix = y / (UI_H - 1)
            draw.line([(0, y), (LEFT_W, y)], fill=tuple(
                round(top[i] + (bottom[i] - top[i]) * mix) for i in range(3)))

        # A soft pool of light behind the handset.
        glow = Image.radial_gradient('L').resize((LEFT_W, UI_H), Image.BILINEAR)
        glow = glow.point(lambda value: round((255 - value) / 255 * 18))
        bg = ImageChops.add(bg, Image.merge('RGB', (
            glow.point(lambda value: round(value * 0.85)),
            glow.point(lambda value: round(value * 0.95)),
            glow)))

        # Contact shadow.
        shadow = Image.new('RGBA', (LEFT_W, UI_H), (0, 0, 0, 0))
        sd = ImageDraw.Draw(shadow)
        top_y = PHONE_TOP + photo_h - 22
        sd.ellipse([phone_x - 34, top_y, phone_x + width + 34, top_y + 54],
                   fill=(0, 0, 0, 150))
        shadow = shadow.filter(ImageFilter.GaussianBlur(15))
        bg = Image.alpha_composite(bg.convert('RGBA'), shadow).convert('RGB')

        bg.paste(phone, (phone_x, PHONE_TOP), phone)
        self._scene_base = bg
        self._phone_size = (width, photo_h)
        self._phone_pos = (phone_x, PHONE_TOP)

        sx, sy = width / source.width, photo_h / source.height
        for label, index, outline in KEYS:
            points = tuple((phone_x + round(x * sx), PHONE_TOP + round(y * sy))
                           for x, y in outline)
            self.key_shapes[label] = points
            xs, ys = zip(*points)
            self.hotspots[label] = (index, (min(xs), min(ys), max(xs), max(ys)))

        left = phone_x + round(SCREEN[0] * sx)
        top_y = PHONE_TOP + round(SCREEN[1] * sy)
        screen_h = round((SCREEN[3] - SCREEN[1]) * sy)
        screen_w = round(screen_h * LCD_WIDTH / LCD_HEIGHT)
        self._screen_rect = (left, top_y, screen_w, screen_h)
        if LcdShader is not None:
            self._shader = LcdShader(screen_w, screen_h, glass=source.crop(SCREEN))

    def _build_canvas(self):
        self.canvas = tk.Canvas(self.root, width=LEFT_W, height=UI_H, bg=BG,
                                highlightthickness=0, bd=0)
        self.canvas.place(x=0, y=0)
        self.canvas.create_line(LEFT_W - 1, 0, LEFT_W - 1, UI_H, fill=LINE)
        if self._scene_base is not None:
            self._scene_photo = self._photo(self._scene_base)
            self.canvas.create_image(0, 0, anchor='nw', image=self._scene_photo)
        self._screen_item = self.canvas.create_image(
            self._screen_rect[0], self._screen_rect[1], anchor='nw')
        self._build_overlays()
        self.canvas.bind('<ButtonPress-1>', self._mouse_press)
        self.canvas.bind('<ButtonRelease-1>', self._mouse_release)
        self.canvas.bind('<Motion>', self._mouse_motion)
        self.canvas.bind('<Leave>', lambda event: self._set_hover(None))

    def _build_overlays(self):
        """Soft glass highlights drawn over the physical keys."""
        if Image is None:
            return
        for label, (_index, (x0, y0, x1, y1)) in self.hotspots.items():
            width, height = x1 - x0, y1 - y0
            points = [(x - x0, y - y0) for x, y in self.key_shapes[label]]
            hover = Image.new('RGBA', (width, height), (0, 0, 0, 0))
            hd = ImageDraw.Draw(hover)
            hd.polygon(points, fill=(255, 255, 255, 13), outline=(255, 255, 255, 22))
            press = Image.new('RGBA', (width, height), (0, 0, 0, 0))
            pd = ImageDraw.Draw(press)
            pd.polygon(points, fill=(0, 0, 0, 76), outline=(255, 255, 255, 30))
            hv = self._photo(hover, alpha=True)
            pv = self._photo(press, alpha=True)
            self._hover_items[label] = self.canvas.create_image(
                x0, y0, anchor='nw', image=hv, state='hidden')
            self._press_items[label] = self.canvas.create_image(
                x0, y0, anchor='nw', image=pv, state='hidden')
            self._hover_items[label + '#photo'] = hv
            self._press_items[label + '#photo'] = pv

    def _build_panel(self):
        panel = tk.Frame(self.root, bg=BG)
        panel.place(x=LEFT_W, y=0, width=UI_W - LEFT_W, height=UI_H)
        inner = tk.Frame(panel, bg=BG)
        inner.pack(fill='both', expand=True, padx=(28, 32), pady=(62, 32))

        tk.Label(inner, text='RH-105  ·  2007', bg=BG, fg=FAINT,
                 font=(SANS, 8)).pack(anchor='w')
        tk.Label(inner, text='Nokia 1208', bg=BG, fg=TEXT,
                 font=(SANS, 26)).pack(anchor='w', pady=(1, 0))
        tk.Label(inner, text='Series 30  ·  CSTN 96 × 68  ·  65k colours',
                 bg=BG, fg=DIM, font=(SANS, 8)).pack(anchor='w', pady=(7, 0))

        self._rule(inner)
        self._label(inner, 'STATUS')
        row = tk.Frame(inner, bg=BG)
        row.pack(anchor='w', fill='x')
        self._dot = tk.Canvas(row, width=10, height=10, bg=BG, highlightthickness=0)
        self._dot.pack(side='left', padx=(0, 8))
        self._dot_id = self._dot.create_oval(2, 2, 8, 8, fill=GREEN, outline='')
        self.status = tk.Label(row, text='Starting', bg=BG, fg=TEXT,
                               font=(SANS, 10, 'bold'))
        self.status.pack(side='left')
        self.detail = tk.Label(inner, text='', bg=BG, fg=DIM,
                               font=(SANS, 8), justify='left')
        self.detail.pack(anchor='w', pady=(5, 0))

        self._rule(inner)
        self._label(inner, 'CONTROLS')
        self._btn_save = PillButton(inner, 'Save handset image', self._save_png)
        self._btn_save.pack(anchor='w', pady=3)
        self._btn_log = PillButton(inner, 'View trace log', self._show_log)
        self._btn_log.pack(anchor='w', pady=3)
        self._btn_restart = PillButton(inner, 'Restart handset', self._restart)
        self._btn_restart.pack(anchor='w', pady=3)
        self._btn_quit = PillButton(inner, 'Quit', self.close, danger=True)
        self._btn_quit.pack(anchor='w', pady=3)

        self._rule(inner)
        self._label(inner, 'KEYBOARD')
        legends = (
            ('F1  F2', 'Left / right softkey'),
            ('↑ ↓ ← →', 'Navigate menus'),
            ('Enter', 'Select / OK'),
            ('F3  F4', 'Call / end call'),
            ('0–9 * #', 'Dial a number'),
        )
        for key, description in legends:
            line = tk.Frame(inner, bg=BG)
            line.pack(anchor='w', fill='x', pady=1)
            tk.Label(line, text=key, bg='#151a20', fg='#aeb6c1',
                     font=(MONO, 8), padx=6, pady=2, width=9,
                     anchor='w').pack(side='left')
            tk.Label(line, text=description, bg=BG, fg=DIM,
                     font=(SANS, 8)).pack(side='left', padx=(9, 0))

        self._rule(inner)
        self._label(inner, 'DISPLAY')
        self._shader_toggle = tk.Checkbutton(
            inner, text='LCD shader', variable=self.shader_enabled,
            command=self._toggle_shader, bg=BG, fg=TEXT, selectcolor=BTN_BG,
            activebackground=BG, activeforeground=TEXT, font=(SANS, 9),
            highlightbackground=BG, highlightcolor=GREEN, highlightthickness=1,
            bd=0, padx=0, takefocus=True,
            state='normal' if self._shader is not None else 'disabled')
        self._shader_toggle.pack(anchor='w', pady=(0, 8))
        for key, value in (
                ('Panel', 'CSTN · passive matrix'),
                ('Window', '96 × 68 px · 65k'),
                ('Audio', 'Ringtones and buzzer')):
            row = tk.Frame(inner, bg=BG)
            row.pack(anchor='w', fill='x', pady=1)
            tk.Label(row, text=key, bg=BG, fg=FAINT, width=8, anchor='w',
                     font=(SANS, 7)).pack(side='left')
            tk.Label(row, text=value, bg=BG, fg=DIM,
                     font=(SANS, 8)).pack(side='left')

        tk.Frame(inner, bg=BG).pack(fill='both', expand=True)
        tk.Label(inner, text='Hold End to power off', bg=BG, fg=FAINT,
                 font=(SANS, 8)).pack(anchor='w')
        tk.Label(inner, text='Preservation build  ·  2007', bg=BG, fg='#353b44',
                 font=(SANS, 7)).pack(anchor='w', pady=(3, 0))

    @staticmethod
    def _label(parent, text):
        tk.Label(parent, text=text, bg=BG, fg=FAINT,
                 font=(SANS, 7)).pack(anchor='w', pady=(0, 7))

    @staticmethod
    def _rule(parent):
        tk.Frame(parent, bg=LINE, height=1).pack(fill='x', pady=(19, 15))

    # -- live screen -----------------------------------------------------
    def _paint_screen(self, rgb=None, *, now_ns=None, frame_ns=None):
        rect = self._screen_rect
        if Image is None:
            return
        if rgb is not None:
            self._screen_rgb = rgb
        if self._shader is not None and self.shader_enabled.get():
            image = self._shader.render(rgb, now_ns=now_ns, frame_ns=frame_ns)
        else:
            image = Image.frombytes('RGB', (LCD_WIDTH, LCD_HEIGHT), self._screen_rgb)
            image = image.resize((rect[2], rect[3]), Image.NEAREST)
        self._screen_pil = image
        self._screen_photo = self._photo(image)
        self.canvas.itemconfigure(self._screen_item, image=self._screen_photo)

    # -- pointer ---------------------------------------------------------
    def _hit(self, x, y):
        for label, (_index, (x0, y0, x1, y1)) in self.hotspots.items():
            if not (x0 <= x < x1 and y0 <= y < y1):
                continue
            inside = False
            points = self.key_shapes[label]
            ax, ay = points[-1]
            for bx, by in points:
                if (ay > y) != (by > y) and x < ax + (y - ay) * (bx - ax) / (by - ay):
                    inside = not inside
                ax, ay = bx, by
            if inside:
                return label
        return None

    def _set_hover(self, label):
        if label == self._hover_label:
            return
        self._hover_label = label
        self._sync_overlays()
        self.canvas.configure(cursor='hand2' if label else '')

    def _mouse_motion(self, event):
        self._set_hover(self._hit(event.x, event.y))

    def _mouse_press(self, event):
        self.root.focus_set()
        label = self._hit(event.x, event.y)
        self._set_hover(label)
        self.input.release('mouse')
        if label is not None:
            self.input.press('mouse', self.hotspots[label][0])
            self._sync_overlays()
        return 'break'

    def _mouse_release(self, _event):
        self.input.release('mouse')
        self._sync_overlays()

    def _sync_overlays(self):
        held = frozenset(self.input.owners.values())
        if held == self._held and self._hover_label == self._drawn_hover:
            return
        for label in self.hotspots:
            pressed = self.hotspots[label][0] in held
            hovered = (label == self._hover_label) and not pressed
            self.canvas.itemconfigure(
                self._press_items[label], state='normal' if pressed else 'hidden')
            self.canvas.itemconfigure(
                self._hover_items[label], state='normal' if hovered else 'hidden')
        self._held = held
        self._drawn_hover = self._hover_label

    # -- keyboard --------------------------------------------------------
    def _after(self, delay, callback):
        def invoke():
            self._callbacks.discard(handle)
            if not self._closed:
                callback()
        handle = self.root.after(delay, invoke)
        self._callbacks.add(handle)
        return handle

    def _cancel(self, handle):
        self.root.after_cancel(handle)
        self._callbacks.discard(handle)

    def _key_press(self, event):
        index = KEY_BINDINGS.get(event.keysym)
        if index is None:
            return
        source = ('keyboard', event.keycode)
        if source in self._releases:
            self._cancel(self._releases.pop(source))
        self.input.press(source, index)
        self._sync_overlays()
        return 'break'

    def _key_release(self, event):
        source = ('keyboard', event.keycode)
        if source not in self.input.owners or source in self._releases:
            return
        # X11 autorepeat synthesizes release/press pairs. A repeated down
        # cancels this release; a real up is delivered once, shortly afterward.
        def release():
            self._releases.pop(source, None)
            self.input.release(source)
            self._sync_overlays()
        self._releases[source] = self._after(25, release)
        return 'break'

    def _release_all(self):
        for handle in self._releases.values():
            self._cancel(handle)
        self._releases.clear()
        self.input.release_all()
        self._sync_overlays()

    def _focus_out(self, event):
        self._after(0, lambda: self._release_all() if self.root.focus_displayof() is None
                    or self.root.focus_displayof().winfo_toplevel() != self.root else None)

    # -- refresh loop ----------------------------------------------------
    def _refresh(self):
        started = time.monotonic_ns()
        emulator = self.emulator
        now = started
        with emulator.lock:
            due = now - self._painted_ns >= PAINT_INTERVAL_NS
            if due and emulator.dirty:
                emulator.dirty = False
                rgb = emulator.lcd.to_rgb()
                written = emulator.lcd.written
                frame_ns = emulator.lcd_updated_ns
            else:
                rgb = None
                frame_ns = None
        settling = (self._shader is not None and self.shader_enabled.get()
                    and self._shader.settling)
        if due and (rgb is not None or settling):
            self._painted_ns = now
            self._paint_screen(rgb, now_ns=now, frame_ns=frame_ns)
            if self._trace_lcd_timing and rgb is not None:
                emulator.log(f'[timing] present pixels={written} wall_ns={time.monotonic_ns()}')

        self._sync_overlays()
        if emulator.running:
            audio = 'audio muted' if emulator.audio_error else 'phone audio streaming'
            if emulator.audio_dropped_bytes:
                audio += ' · overrun'
            status, detail = 'Running', f'{emulator.keys} key events  ·  {audio}'
            dot = GREEN
        else:
            status = 'Stopped'
            detail = emulator.stop_reason or 'Restart to boot the handset'
            dot = RED
        if status != self._status_text:
            self.status.configure(text=status, fg=TEXT if emulator.running else '#d9b3b3')
            self._dot.itemconfigure(self._dot_id, fill=dot)
            self._status_text = status
        if detail != self._detail_text:
            self.detail.configure(text=detail)
            self._detail_text = detail
        if self._log_window and self._log_window.winfo_exists():
            revision, text = emulator.log.snapshot()
            if revision != self._log_revision:
                self._log_text.configure(state='normal')
                self._log_text.delete('1.0', 'end')
                self._log_text.insert('end', text)
                self._log_text.configure(state='disabled')
                self._log_text.see('end')
                self._log_revision = revision
        # Account for render time so it does not become another frame of wait.
        active = settling or rgb is not None
        interval = PAINT_INTERVAL_NS if active else 8_000_000
        remaining = interval - (time.monotonic_ns() - started)
        self._after(max(1, (remaining + 999_999) // 1_000_000), self._refresh)

    # -- actions ---------------------------------------------------------
    def _toggle_shader(self):
        self._release_all()
        if self._shader is not None:
            self._shader.reset()
        with self.emulator.lock:
            rgb = self.emulator.lcd.to_rgb()
            frame_ns = self.emulator.lcd_updated_ns
        self._painted_ns = time.monotonic_ns()
        self._paint_screen(rgb, now_ns=self._painted_ns, frame_ns=frame_ns)

    def _restart(self):
        self._release_all()
        self._set_hover(None)
        if self._shader is not None:
            self._shader.reset()
        self.emulator.start()

    def _save_png(self):
        self._release_all()
        path = filedialog.asksaveasfilename(
            parent=self.root, title='Save the handset', defaultextension='.png',
            initialfile='nokia1208.png', filetypes=[('PNG image', '*.png')])
        if not path:
            return
        try:
            if self._scene_base is not None and self._screen_pil is not None:
                scene = self._scene_base.copy()
                scene.paste(self._screen_pil, (self._screen_rect[0], self._screen_rect[1]))
                scene.save(path)
            else:
                write_png(path, self.emulator.lcd, 4)
            self.emulator.log(f'[gui] wrote {path}')
        except OSError as error:
            self.emulator.log(f'[gui] save failed: {error}')

    def _show_log(self):
        self._release_all()
        if self._log_window and self._log_window.winfo_exists():
            self._log_window.lift()
            return
        window = tk.Toplevel(self.root)
        self._log_window = window
        window.title('RH-105 trace')
        window.geometry('780x420')
        window.configure(bg=BG)
        header = tk.Frame(window, bg=BG)
        header.pack(fill='x', padx=16, pady=(13, 7))
        tk.Label(header, text='RH-105 TRACE', bg=BG, fg=DIM,
                 font=(SANS, 8)).pack(side='left')
        tk.Label(header, text='● live', bg=BG, fg=GREEN,
                 font=(SANS, 8)).pack(side='right')
        body = tk.Frame(window, bg=BG)
        body.pack(fill='both', expand=True, padx=16, pady=(0, 16))
        scrollbar = ttk.Scrollbar(body)
        scrollbar.pack(side='right', fill='y')
        self._log_text = tk.Text(
            body, wrap='none', state='disabled', bg='#07090b', fg='#aeb6c1',
            insertbackground=TEXT, bd=0, highlightthickness=0,
            font=(MONO, 8), padx=12, pady=10, yscrollcommand=scrollbar.set)
        self._log_text.pack(side='left', fill='both', expand=True)
        scrollbar.configure(command=self._log_text.yview)
        self._log_revision = -1

    def close(self):
        self._release_all()
        self._closed = True
        for handle in list(self._callbacks):
            self._cancel(handle)
        self.emulator.stop()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instruction-limit', type=int, default=0,
                        help='stop after N instructions; 0 (the default) is unlimited')
    parser.add_argument('--unthrottled', action='store_true',
                        help='run as fast as possible instead of pacing to real time')
    parser.add_argument('--scale', type=float, default=1.0,
                        help='handset photograph scale in the window; default 1.0')
    parser.add_argument('--sim', action=argparse.BooleanOptionalAction, default=True,
                        help='insert the virtual SIM by default; --no-sim disables it')
    parser.add_argument('--tone', type=int, choices=range(1, 2048), metavar='DIVIDER',
                        help='diagnostic forced buzzer tone; not firmware audio')
    args = parser.parse_args()
    if not 0 <= args.instruction_limit <= 10_000_000_000:
        parser.error('--instruction-limit must be between 0 and 10000000000')
    if not 0 < args.scale <= 4:
        parser.error('--scale must be greater than 0 and at most 4')
    log = LogBuffer()
    emulator = Emulator(1, args.instruction_limit, args.tone, log,
                        realtime=not args.unthrottled, sim=args.sim)
    try:
        root = tk.Tk()
        root.withdraw()
    except tk.TclError as error:
        print(f'GUI unavailable: {error}', file=sys.stderr)
        return 1
    try:
        identity = hashlib.sha256(str(STORAGE.resolve()).encode()).hexdigest()[:16]
        app_name = f'rh105_{identity}'
        registered = root.tk.call('tk', 'appname', app_name)
        if registered != app_name:
            try:
                for command in (('wm', 'deiconify', '.'), ('raise', '.'),
                                ('focus', '-force', '.')):
                    root.tk.call('send', app_name, *command)
            except tk.TclError:
                pass
            print('Nokia 1208 is already running; use its existing window.', file=sys.stderr)
            return 0
        if not emulator.start():
            return 1
        Rh105Gui(root, emulator, args.scale)
        root.deiconify()
        root.mainloop()
    finally:
        emulator.stop()
        try:
            root.destroy()
        except tk.TclError:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
