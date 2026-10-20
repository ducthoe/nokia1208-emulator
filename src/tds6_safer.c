/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#include "tds6_safer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t be32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
           (uint32_t)bytes[2] << 8 | bytes[3];
}

int tds6_safer_load_profile(const char *path, Tds6SaferProfile *profile) {
    FILE *input = fopen(path, "rb");
    if (!input) { perror(path); return 0; }
    uint8_t *image = malloc(0x20000);
    if (!image) { fclose(input); return 0; }
    size_t length = fread(image, 1, 0x20000, input);
    int extra = fgetc(input);
    int valid = !ferror(input) && length == 0x20000 && extra == EOF;
    fclose(input);
    if (valid) {
        valid = be32(image) == 0xD58E &&
                !memcmp(image + 0x11A20, "V  3.20\n30-10-02\nTDS-6 ", 23);
    }
    if (!valid) {
        fprintf(stderr, "Expected the analyzed 128 KiB TDS6 v3.20 H8 image\n");
        free(image);
        return 0;
    }
    uint32_t salt = be32(image + 0xD7C8), root = be32(image + 0xD7CC);
    if (salt > 0x20000 - sizeof(profile->salt) || root > 0x20000 - sizeof(profile->root)) {
        fprintf(stderr, "TDS6 key pointers fall outside the supplied image\n");
        free(image);
        return 0;
    }
    memcpy(profile->root, image + root, sizeof(profile->root));
    memcpy(profile->salt, image + salt, sizeof(profile->salt));
    memcpy(profile->signature, image + 0xD7C0, sizeof(profile->signature));
    free(image);
    return 1;
}

/* TDS6 0x325A/0x3360: lookup tables, mode derivation and 18 key rows. */
static void prepare(uint8_t *work, const Tds6SaferProfile *profile, uint8_t mode) {
    uint8_t *exp = work, *log = work + 0x100, *keys = work + 0x200;
    unsigned power = 1;
    for (unsigned i = 0; i < 256; ++i) {
        exp[i] = (uint8_t)power;
        log[(uint8_t)power] = (uint8_t)i;
        power = power * 45 % 257;
    }
    uint8_t salt = (mode & 15) ? profile->salt[mode & 15] : 0;
    if (mode & 0x20) salt ^= profile->salt[16];
    else if (mode & 0x40) salt ^= profile->salt[17];
    for (unsigned j = 0; j < 8; ++j) {
        uint8_t key = (mode & 0x10) ? keys[j] : 0;
        key ^= salt ^ profile->root[j];
        if (mode & 0x80) key ^= profile->signature[j];
        keys[j] = key;
        for (unsigned r = 1; r <= 17; ++r) {
            key = (uint8_t)((key << 3) | (key >> 5));
            keys[8 * r + j] = (uint8_t)(key + exp[exp[9 * (r + 1) + j + 1]]);
        }
    }
}

static void pht(uint8_t *data, int inverse) {
    for (unsigned j = 0; j < 8; j += 2) {
        unsigned a = data[j], b = data[j + 1];
        data[j] = (uint8_t)(inverse ? a - b : 2 * a + b);
        data[j + 1] = (uint8_t)(inverse ? 2 * b - a : a + b);
    }
}

static void permute(uint8_t *data, int inverse) {
    static const unsigned order[2][8] = {
        {0, 2, 4, 6, 1, 3, 5, 7},
        {0, 4, 1, 5, 2, 6, 3, 7},
    };
    uint8_t old[8];
    memcpy(old, data, sizeof(old));
    for (unsigned j = 0; j < 8; ++j) data[j] = old[order[inverse][j]];
}

/* Encode rounds are inline at 0x302C; decode block starts at 0x35D4. */
static void block(uint8_t *data, const uint8_t *work, int decode) {
    const uint8_t *exp = work, *log = work + 0x100, *keys = work + 0x200;
    if (decode) {
        for (unsigned j = 0; j < 8; ++j)
            data[j] = (0x99 & (0x80u >> j)) ? data[j] ^ keys[128 + j] :
                      (uint8_t)(data[j] - keys[128 + j]);
    }
    for (unsigned step = 0; step < 8; ++step) {
        unsigned round = decode ? 7 - step : step;
        const uint8_t *first = keys + round * 16, *second = first + 8;
        if (decode) {
            pht(data, 1);
            for (unsigned stage = 0; stage < 2; ++stage) {
                permute(data, 1);
                pht(data, 1);
            }
        }
        for (unsigned j = 0; j < 8; ++j) {
            if (0x99 & (0x80u >> j)) {
                data[j] = decode ? log[(uint8_t)(data[j] - second[j])] ^ first[j] :
                          (uint8_t)(exp[data[j] ^ first[j]] + second[j]);
            } else {
                data[j] = decode ? (uint8_t)(exp[data[j] ^ second[j]] - first[j]) :
                          log[(uint8_t)(data[j] + first[j])] ^ second[j];
            }
        }
        if (!decode) {
            for (unsigned stage = 0; stage < 2; ++stage) {
                pht(data, 0);
                permute(data, 0);
            }
            pht(data, 0);
        }
    }
    if (!decode) {
        for (unsigned j = 0; j < 8; ++j)
            data[j] = (0x99 & (0x80u >> j)) ? data[j] ^ keys[128 + j] :
                      (uint8_t)(data[j] + keys[128 + j]);
    }
}

void tds6_safer_cbc(uint8_t *data, size_t length, uint8_t *workspace,
                   const Tds6SaferProfile *profile, uint8_t mode, int decode) {
    uint8_t previous[8] = {0}, saved[8];
    prepare(workspace, profile, mode);
    for (size_t offset = 0; offset < length; offset += 8) {
        uint8_t *current = data + offset;
        if (decode) memcpy(saved, current, sizeof(saved));
        else for (unsigned j = 0; j < 8; ++j) current[j] ^= previous[j];
        block(current, workspace, decode);
        if (decode) {
            for (unsigned j = 0; j < 8; ++j) current[j] ^= previous[j];
            memcpy(previous, saved, sizeof(previous));
        } else memcpy(previous, current, sizeof(previous));
    }
    memset(workspace, 0, TDS6_SAFER_WORKSPACE);
}
