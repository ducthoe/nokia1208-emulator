/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#ifndef TDS6_SAFER_H
#define TDS6_SAFER_H

#include <stddef.h>
#include <stdint.h>

#define TDS6_SAFER_WORKSPACE 0x290u

typedef struct {
    uint8_t root[8];
    uint8_t salt[18];
    uint8_t signature[8];
} Tds6SaferProfile;

int tds6_safer_load_profile(const char *path, Tds6SaferProfile *profile);
void tds6_safer_cbc(uint8_t *data, size_t length, uint8_t *workspace,
                   const Tds6SaferProfile *profile, uint8_t mode, int decode);

#endif
