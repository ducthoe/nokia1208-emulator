# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Validate and prepare local RH-105 firmware for the emulator."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from nokia1208 import (
    FLASH_BASE, MAX_IMAGE_SIZE, Firmware, FirmwareError,
    decrypt_image, parse_firmware, recover_key,
)


def assemble_flash(images: list[tuple[Firmware, bytes]]) -> tuple[bytes, int]:
    end = max(firmware.end for firmware, _ in images)
    if any(firmware.base < FLASH_BASE for firmware, _ in images) or end - FLASH_BASE > MAX_IMAGE_SIZE:
        raise FirmwareError('Unexpected RH-105 flash range')
    result = bytearray(b'\xff') * (end - FLASH_BASE)
    covered = bytearray(len(result))
    overlap = 0
    for firmware, image in images:
        if len(image) != firmware.end - firmware.base:
            raise FirmwareError('Image length does not match its flash map')
        for block in firmware.blocks:
            start = block.address - firmware.base
            for index, value in enumerate(image[start:start + len(block.data)], block.address - FLASH_BASE):
                if covered[index]:
                    if result[index] != value:
                        raise FirmwareError(f'Conflicting flash images at {FLASH_BASE + index:#010x}')
                    overlap += 1
                result[index] = value
                covered[index] = 1
    return bytes(result), overlap


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2) + '\n').encode()


def prepare(mcu_path: Path, ppm_path: Path, content_path: Path, output: Path) -> dict:
    paths = [('mcu', mcu_path), ('ppm', ppm_path), ('content', content_path)]
    sources = {kind: parse_firmware(path.read_bytes()) for kind, path in paths}
    if any(f.metadata.get(0xD4) != bytes.fromhex('2292') for f in sources.values()):
        raise FirmwareError('This preparation profile requires ASIC 0x2292')
    if sources['mcu'].base != FLASH_BASE:
        raise FirmwareError('Unexpected MCU base address')
    key = recover_key(sources['mcu'], True)
    images = {kind: decrypt_image(f, key, kind == 'mcu') for kind, f in sources.items()}
    version = b'V 6.00\n30-09-09\nRH-105\n(c) NMP\0'
    if version not in images['mcu'] or images['mcu'][0x100] != 0xEA:
        raise FirmwareError('MCU decryption did not produce the expected RH-105 v6.00 image')
    ppm_offset = images['ppm'].find(b'PPM\0' + version)
    if ppm_offset < 0:
        raise FirmwareError('Missing matching RH-105 v6.00 PPM header')
    if not images['content'].startswith(b'LIST') or images['content'][8:12] != b'NAI\0':
        raise FirmwareError('Content did not decrypt to a Nokia NAI container')
    flash, overlap = assemble_flash([(f, images[kind]) for kind, f in sources.items()])
    files = {f'{kind}.bin': bytes(data) for kind, data in images.items()}
    files['flash.bin'] = flash
    raw_flash, _ = assemble_flash([(f, f.image()) for f in sources.values()])
    files['raw-flash.bin'] = raw_flash
    manifest = {
        'status': 'firmware_prepared; phone_not_booted',
        'firmware': 'Nokia 1208 RH-105 v6.00, 30-09-09',
        'crypt_key': f'0x{key:04x}',
        'flash_base': f'0x{FLASH_BASE:08x}',
        'flash_end_exclusive': f'0x{FLASH_BASE + len(flash):08x}',
        'matching_overlap_bytes': overlap,
        'ppm_header_address': f'0x{sources["ppm"].base + ppm_offset:08x}',
        'sources': {kind: dict(path=str(path), **sources[kind].summary()) for kind, path in paths},
        'outputs': {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                    for name, data in files.items()},
        'missing': ['cold boot with MCU boot ROM',
                    'verified UPPCosto/LITTI reset state and timing',
                    'cellular service and DSP speech', 'physical SIM access'],
    }
    files['manifest.json'] = json_bytes(manifest)
    for name, data in files.items():
        path = output / name
        if path.exists() and path.read_bytes() != data:
            raise FirmwareError(f'Refusing to replace different output: {path}')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = output / name
        if not path.exists():
            with path.open('xb') as handle:
                handle.write(data)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mcu', type=Path, default=Path('firmware/rh105_06.000'))
    parser.add_argument('--ppm', type=Path, default=Path('firmware/rh105_06.00eo'))
    parser.add_argument('--content', type=Path, default=Path('firmware/rh1050_nai6.00eo'))
    parser.add_argument('--output', type=Path, default=Path('build/rh105-eo'))
    args = parser.parse_args()
    try:
        report = prepare(args.mcu, args.ppm, args.content, args.output)
        print(f'Prepared {report["firmware"]} in {args.output}')
        print(f'Checked {report["matching_overlap_bytes"]:,} identical MCU/PPM overlap bytes.')
        print('Firmware is ready. Run ./run to open the handset.')
        return 0
    except (OSError, FirmwareError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
