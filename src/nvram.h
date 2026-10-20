/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#ifndef RH105_NVRAM_H
#define RH105_NVRAM_H

#include <stddef.h>
#include <stdint.h>

#define NVRAM_BASE 0x013b0000u
#define NVRAM_SEED_SIZE 0x00050000u
#define NVRAM_SIZE 0x00c50000u

typedef struct {
    char *path;
    int lock_fd;
    unsigned loaded, saves;
} NvramStore;

int nvram_load_image(const char *path, uint8_t *data);
int nvram_open(NvramStore *store, const char *path, uint8_t *data);
int nvram_save(NvramStore *store, const uint8_t *data);
void nvram_close(NvramStore *store);

#endif
