/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#define _POSIX_C_SOURCE 200809L
#include "nvram.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define BLOCK_SIZE 65536u
#define BLOCK_COUNT (NVRAM_SIZE / BLOCK_SIZE)
static const uint8_t magic[8] = {'R','H','1','0','5','N','V',1};

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t value) {
    p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value;
}

static uint32_t checksum(const uint8_t *data) {
    uint32_t crc = UINT32_MAX;
    for (unsigned i = 0; i < BLOCK_SIZE; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    return ~crc;
}

static int populated(const uint8_t *data) {
    for (unsigned i = 0; i < BLOCK_SIZE; ++i)
        if (data[i] != 0xff) return 1;
    return 0;
}

int nvram_load_image(const char *path, uint8_t *data) {
    FILE *file = fopen(path, "rb");
    if (!file) { perror(path); return 0; }
    uint8_t header[20];
    if (fread(header, 1, sizeof(header), file) != sizeof(header)) goto invalid;
    if (memcmp(header, magic, sizeof(magic))) {
        /* Older factory seeds contain just the five PMM banks. */
        if (header[0] != 0xf0 || header[1] != 0xf0 || fseek(file, 0, SEEK_SET)) goto invalid;
        memset(data, 0xff, NVRAM_SIZE);
        size_t count = fread(data, 1, NVRAM_SEED_SIZE, file);
        if (count != NVRAM_SEED_SIZE || fgetc(file) != EOF || ferror(file)) goto invalid;
    } else {
        uint32_t count = be32(header + 16), previous = 0;
        if (be32(header + 8) != NVRAM_BASE || be32(header + 12) != NVRAM_SIZE ||
            count > BLOCK_COUNT) goto invalid;
        memset(data, 0xff, NVRAM_SIZE);
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t record[8];
            if (fread(record, 1, sizeof(record), file) != sizeof(record)) goto invalid;
            uint32_t index = be32(record);
            if (index >= BLOCK_COUNT || (i && index <= previous)) goto invalid;
            uint8_t *block = data + index * BLOCK_SIZE;
            if (fread(block, 1, BLOCK_SIZE, file) != BLOCK_SIZE ||
                checksum(block) != be32(record + 4)) goto invalid;
            previous = index;
        }
        if (fgetc(file) != EOF || ferror(file)) goto invalid;
    }
    fclose(file);
    return 1;
invalid:
    fprintf(stderr, "Invalid or damaged RH-105 storage image: %s\n", path);
    fclose(file);
    return 0;
}

int nvram_open(NvramStore *store, const char *path, uint8_t *data) {
    memset(store, 0, sizeof(*store));
    store->lock_fd = -1;
    if (!path) return 1;
    store->path = strdup(path);
    char *lock_path = malloc(strlen(path) + 6);
    if (!store->path || !lock_path) { free(lock_path); nvram_close(store); return 0; }
    sprintf(lock_path, "%s.lock", path);
    store->lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
    free(lock_path);
    if (store->lock_fd < 0 || flock(store->lock_fd, LOCK_EX | LOCK_NB)) {
        fprintf(stderr, "Cannot lock handset storage %s: %s\n", path, strerror(errno));
        nvram_close(store);
        return 0;
    }
    if (access(path, F_OK)) {
        if (errno == ENOENT) return 1;
        perror(path); nvram_close(store); return 0;
    }
    if (!nvram_load_image(path, data)) { nvram_close(store); return 0; }
    store->loaded = 1;
    return 1;
}

int nvram_save(NvramStore *store, const uint8_t *data) {
    if (!store->path) return 1;
    char *temporary = malloc(strlen(store->path) + 12);
    if (!temporary) return 0;
    sprintf(temporary, "%s.tmp.XXXXXX", store->path);
    int fd = mkstemp(temporary), success = 0;
    if (fd < 0) { perror(temporary); free(temporary); return 0; }
    FILE *file = fdopen(fd, "wb");
    if (!file) { close(fd); goto done; }
    uint32_t count = 0;
    for (unsigned i = 0; i < BLOCK_COUNT; ++i)
        count += populated(data + i * BLOCK_SIZE);
    uint8_t header[20];
    memcpy(header, magic, sizeof(magic));
    put32(header + 8, NVRAM_BASE); put32(header + 12, NVRAM_SIZE); put32(header + 16, count);
    int failed = fwrite(header, 1, sizeof(header), file) != sizeof(header);
    for (unsigned i = 0; i < BLOCK_COUNT && !failed; ++i) {
        const uint8_t *block = data + i * BLOCK_SIZE;
        if (!populated(block)) continue;
        uint8_t record[8];
        put32(record, i); put32(record + 4, checksum(block));
        failed = fwrite(record, 1, sizeof(record), file) != sizeof(record) ||
                 fwrite(block, 1, BLOCK_SIZE, file) != BLOCK_SIZE;
    }
    if (fflush(file) || fsync(fd)) failed = 1;
    if (fclose(file)) failed = 1;
    if (!failed && !rename(temporary, store->path)) {
        success = 1;
        store->loaded = 1;
        ++store->saves;
    }
done:
    if (!success) { perror(store->path); unlink(temporary); }
    free(temporary);
    return success;
}

void nvram_close(NvramStore *store) {
    if (store->lock_fd >= 0) close(store->lock_fd);
    free(store->path);
    store->path = NULL;
    store->lock_fd = -1;
}
