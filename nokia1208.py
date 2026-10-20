# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

"""Inspect and decrypt RH-105 Phoenix images for emulator development."""

from __future__ import annotations

import argparse
from array import array
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sys


FLASH_BASE = 0x01000000
CRYPT_START = FLASH_BASE + 0x84
MAX_IMAGE_SIZE = 32 * 1024 * 1024

# Mathematical parameters published by g3gg0's DCT4Crypt (see README.md).
DATA_BASIS = tuple(int(s, 16) for s in (
    "1221 a91a 52a5 0908 a918 1020 ffff 52a1 "
    "0100 1220 ad1a 0900 1000 2908 5221 a908"
).split())
ADDRESS_BASIS = tuple(int(s, 16) for s in (
    "0fae 3e7f c99f d6f7 a71b 14c4 52a5 cbb1 "
    "4285 efdf dff7 5080 ee9f 0000 8432 5221 "
    "4084 a91a 56e7 b93a 5b21 a818 0000 efdf"
).split())
ADDRESS_TERMS = tuple(tuple(int(s, 16) for s in pair.split(':')) for pair in (
    "140:1000 220:52a1 480:1221 600:b928 810:5221 840:1220 "
    "900:2008 1020:1221 1080:0908 1100:52a1 2020:0100 "
    "2080:fbbd 4010:a91a 4040:a908 8008:2908 9000:1000 "
    "a000:bd3a 10010:ad1a 10040:5221 10400:0908 20200:53a5 "
    "40040:a91a 44000:1b20 80100:a918 800000:b908"
).split())


class FirmwareError(ValueError):
    pass


@dataclass(frozen=True)
class Block:
    address: int
    data: bytes
    file_offset: int

    @property
    def end(self) -> int:
        return self.address + len(self.data)


@dataclass(frozen=True)
class Firmware:
    metadata: dict[int, bytes]
    blocks: tuple[Block, ...]
    sha256: str

    @property
    def base(self) -> int:
        return self.blocks[0].address

    @property
    def end(self) -> int:
        return self.blocks[-1].end

    def image(self) -> bytearray:
        result = bytearray(b'\xff') * (self.end - self.base)
        for block in self.blocks:
            offset = block.address - self.base
            result[offset:offset + len(block.data)] = block.data
        return result

    def summary(self) -> dict:
        return {
            'sha256': self.sha256,
            'algorithm': self.metadata.get(0xC2, b'').rstrip(b'\0').decode('ascii'),
            'asic_id': self.metadata.get(0xD4, b'').hex(),
            'blocks': len(self.blocks),
            'base': f'0x{self.base:08x}',
            'end_exclusive': f'0x{self.end:08x}',
            'payload_bytes': sum(len(b.data) for b in self.blocks),
            'gap_bytes': self.end - self.base - sum(len(b.data) for b in self.blocks),
            'container_checksums': 'valid',
        }


def parse_firmware(data: bytes) -> Firmware:
    if len(data) < 9 or data[0] != 0xA2:
        raise FirmwareError('Expected a Phoenix A2 container')
    header_end = 5 + int.from_bytes(data[1:5], 'big')
    if not 9 <= header_end <= len(data):
        raise FirmwareError('Invalid container header length')
    count = int.from_bytes(data[5:9], 'big')
    metadata = {}
    offset = 9
    for _ in range(count):
        if offset + 2 > header_end:
            raise FirmwareError('Truncated metadata tag')
        tag, size = data[offset:offset + 2]
        offset += 2
        if offset + size > header_end or tag in metadata:
            raise FirmwareError('Truncated or duplicate metadata value')
        metadata[tag] = data[offset:offset + size]
        offset += size
    if offset != header_end:
        raise FirmwareError('Metadata count does not match header length')
    if metadata.get(0xC2) != b'DCT4\0':
        raise FirmwareError('Expected DCT4 firmware')

    blocks = []
    while offset < len(data):
        header = data[offset:offset + 10]
        if len(header) < 10 or header[0] != 0x14:
            raise FirmwareError(f'Unsupported or truncated block at file offset {offset:#x}')
        if sum(header[1:]) & 0xFF != 0xFF:
            raise FirmwareError(f'Block header checksum mismatch at {offset:#x}')
        address = int.from_bytes(header[1:5], 'big')
        size = int.from_bytes(header[6:9], 'big')
        end = offset + 10 + size
        if not size or end > len(data):
            raise FirmwareError(f'Truncated or empty payload at {offset:#x}')
        payload = data[offset + 10:end]
        if (sum(payload) + header[5]) & 0xFF:
            raise FirmwareError(f'Payload checksum mismatch at {offset:#x}')
        if address & 1 or size & 1 or address + size > 0x100000000:
            raise FirmwareError('Invalid halfword-aligned flash range')
        blocks.append(Block(address, payload, offset))
        offset = end
    if not blocks:
        raise FirmwareError('Container has no flash blocks')
    blocks.sort(key=lambda b: b.address)
    for previous, current in zip(blocks, blocks[1:]):
        if previous.end > current.address:
            raise FirmwareError('Overlapping flash blocks')
    if blocks[-1].end - blocks[0].address > MAX_IMAGE_SIZE:
        raise FirmwareError('Flash span exceeds 32 MiB')
    return Firmware(metadata, tuple(blocks), hashlib.sha256(data).hexdigest())


def address_mask(address: int) -> int:
    result = 0
    for bit, value in enumerate(ADDRESS_BASIS, 1):
        if address & (1 << bit):
            result ^= value
    for bits, value in ADDRESS_TERMS:
        if address & bits == bits:
            result ^= value
    return result


@lru_cache(maxsize=1)
def inverse_table() -> array:
    encoded = array('H', [0]) * 65536
    decoded = array('H', [0]) * 65536
    for value in range(1, 65536):
        low = value & -value
        encoded[value] = encoded[value ^ low] ^ DATA_BASIS[low.bit_length() - 1]
    if len(set(encoded)) != 65536:
        raise FirmwareError('Cipher basis is not invertible')
    for value, cipher in enumerate(encoded):
        decoded[cipher] = value
    return decoded


def decode_word(cipher: int, address: int, key: int = 0) -> int:
    return inverse_table()[cipher ^ address_mask(address)] ^ key


@lru_cache(maxsize=1)
def low_address_table() -> array:
    return array('H', (address_mask(a) for a in range(0, 65536, 2)))


def decrypt_image(firmware: Firmware, key: int, mcu: bool) -> bytearray:
    result = firmware.image()
    inverse = inverse_table()
    low_masks = low_address_table()
    cross_terms = [(bits, value) for bits, value in ADDRESS_TERMS
                   if bits >> 16 and bits & 0xFFFF]
    # Only supplied bytes are transformed; gaps stay erased, including 0x2c..0x64.
    for block in firmware.blocks:
        start = max(block.address, CRYPT_START) if mcu else block.address
        for chunk in range(start & ~0xFFFF, block.end, 65536):
            high_mask = address_mask(chunk)
            active_terms = [(bits & 0xFFFF, value) for bits, value in cross_terms
                            if (chunk & (bits & ~0xFFFF)) == (bits & ~0xFFFF)]
            for address in range(max(start, chunk), min(block.end, chunk + 65536), 2):
                low = address & 0xFFFF
                mask = low_masks[low >> 1] ^ high_mask
                for bits, value in active_terms:
                    if low & bits == bits:
                        mask ^= value
                offset = address - firmware.base
                cipher = (result[offset] << 8) | result[offset + 1]
                plain = inverse[cipher ^ mask] ^ key
                result[offset] = plain >> 8
                result[offset + 1] = plain & 0xFF
    return result


def recover_key(firmware: Firmware, mcu: bool) -> int:
    address = CRYPT_START if mcu else firmware.base
    expected = 0xFFFF if mcu else 0x5050
    for block in firmware.blocks:
        if block.address <= address < block.end - 1:
            offset = address - block.address
            return decode_word(int.from_bytes(block.data[offset:offset + 2], 'big'), address) ^ expected
    raise FirmwareError(f'Key recovery word at {address:#x} is absent')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--decrypt', type=Path, metavar='OUTPUT', help='Write a decrypted flat image')
    parser.add_argument('--kind', choices=('mcu', 'ppm'), help='Required for decryption')
    parser.add_argument('--key', type=lambda s: int(s, 0), help='Explicit 16-bit cipher key')
    args = parser.parse_args()
    if args.decrypt and not args.kind:
        parser.error('--decrypt requires --kind mcu or --kind ppm')
    if args.key is not None and not 0 <= args.key <= 0xFFFF:
        parser.error('--key must fit in 16 bits')
    try:
        firmware = parse_firmware(args.image.read_bytes())
        summary = firmware.summary()
        if args.decrypt:
            if args.decrypt.resolve() == args.image.resolve():
                raise FirmwareError('Output must differ from input')
            mcu = args.kind == 'mcu'
            if mcu and firmware.base != FLASH_BASE:
                raise FirmwareError('RH-105 MCU must begin at 0x01000000')
            key = args.key if args.key is not None else recover_key(firmware, mcu)
            decrypted = decrypt_image(firmware, key, mcu)
            if mcu:
                if b'RH-105\n' not in decrypted or decrypted[0x100] != 0xEA:
                    raise FirmwareError('Decryption did not produce RH-105 code; output not written')
            else:
                marker = decrypted.find(b'PPM\0V ')
                if marker < 0 or b'RH-105\n' not in decrypted[marker:marker + 128]:
                    raise FirmwareError('No RH-105 PPM header found; use the MCU key with --key')
                summary['ppm_header_address'] = f'0x{firmware.base + marker:08x}'
            with args.decrypt.open('xb') as output:
                output.write(decrypted)
            summary.update(crypt_key=f'0x{key:04x}', output=str(args.decrypt),
                           output_sha256=hashlib.sha256(decrypted).hexdigest(),
                           key_recovery='known-plaintext assumption' if args.key is None else 'explicit')
        print(json.dumps(summary, indent=2))
        return 0
    except (OSError, FirmwareError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
