<!-- SPDX-FileCopyrightText: 2026 ducthoe
SPDX-License-Identifier: GPL-3.0-only -->

# Nokia 1208 emulator

An experimental emulator for Nokia 1208 / RH-105 v6.00 firmware, with a handset
window, keyboard and mouse controls, LCD effects, ringtones, a virtual SIM, and
persistent phone settings. Cellular service, DSP speech, and physical SIM access
are not implemented. Hardware timing and some peripheral behavior remain
approximate.

## Requirements

Linux with Python 3.10 or newer, a C11 compiler, Make, and an X11 display.
The window uses Tk and Pillow; audio playback uses ALSA's `aplay`.

On Debian or Ubuntu:

```sh
sudo apt install build-essential python3 python3-tk python3-pil alsa-utils
```

For a Python environment that does not already have Pillow:

```sh
python3 -m pip install -r requirements.txt
```

The ARM CPU dependency and the four required firmware inputs are included.
Building and preparing firmware need no downloads once the system dependencies
are installed.

## Run

```sh
./run
```

This prepares the included EO firmware, compiles the emulator, and opens the
handset. It works when called from another directory too. Additional options
are passed to the window:

```sh
./run --no-sim
./run --unthrottled
```

The equivalent individual steps are:

```sh
make prepare
make
python3 tools/rh105_gui.py
```

Use the mouse to press and hold handset keys, or use the keyboard:

| Key | Action |
| --- | --- |
| F1 / F2 | Left / right softkey |
| Arrow keys | Navigate |
| Enter | Select / OK |
| F3 / F4 | Call / end or power |
| 0–9, `*`, `#` | Dial |

The window includes restart, image saving, and an LCD shader toggle. Its log
viewer retains recent output in memory. Set `RH105_VERBOSE=1` to also send that
output to the terminal.

Phone settings are created in `state/nvram.bin` on first use, seeded from
`assets/rh105_factory_nvram.bin`. To start fresh, close the handset and move or
remove `state/nvram.bin`. The firmware inputs remain unchanged.

## Firmware inputs

The four required inputs are kept in `firmware/`:

| File | Purpose |
| --- | --- |
| `firmware/rh105_06.000` | RH-105 v6.00 MCU image |
| `firmware/rh105_06.00eo` | Matching EO language image |
| `firmware/rh1050_nai6.00eo` | Matching EO content pack |
| `firmware/TDS6.BIN` | TDS6 v3.20 cipher profile used by the development ROM model |

`prepare.py` validates and decrypts the update containers into `build/rh105-eo/`.
It refuses to overwrite differing prepared files. Run `make clean` before
preparing a different set of inputs. `SHA256SUMS` records the included firmware
and runtime assets; verify them with `sha256sum -c SHA256SUMS`.

The window selects the development ROM model and a blank virtual identity so
the supplied firmware can start with the virtual SIM. No separate MCU boot ROM
is included. A strict native run is also available:

```sh
./build/rh105 build/rh105-eo/flash.bin --raw-flash=build/rh105-eo/raw-flash.bin
```

The native runner writes a JSON execution report. Exit status 1 means invalid
input or a command error; status 2 means execution stopped, including reaching
an instruction limit or unsupported hardware. The GUI normally runs until closed.

## Cleanup

```sh
make clean  # Remove build output and Python caches; keep phone settings
```

Builds write generated files under `build/` and Python cache
directories. Saved phone state, logs, traces, recordings, and generated images
are excluded by `.gitignore`.

See [THIRD_PARTY.md](THIRD_PARTY.md) for source credits and existing license
information.

## License

The project's original source, scripts, configuration, and documentation are
licensed under the GNU General Public License, version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE) for the full terms and warranty disclaimer.

The vendored mGBA code retains its MPL-2.0 notices and is additionally available
under GPL-3.0-only as part of this combined work, using MPL 2.0 section 3.3.
The firmware, handset photograph, and firmware-derived storage seed are excluded
from the GPL grant. Each binary has a `.license` sidecar recording its status;
see [THIRD_PARTY.md](THIRD_PARTY.md) for the scope and original notices.
