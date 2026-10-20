/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#ifndef RH105_VIRTUAL_SIM_H
#define RH105_VIRTUAL_SIM_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t id;
    uint16_t directory;
    uint16_t size;
    uint8_t record_size;
    uint8_t data[512];
} VirtualSimFile;

typedef struct {
    uint16_t directory, selected;
    VirtualSimFile files[20];
    unsigned file_count, commands;
    uint8_t response[32];
    unsigned response_length;
} VirtualSim;

void virtual_sim_init(VirtualSim *sim);
size_t virtual_sim_exchange(VirtualSim *sim, const uint8_t *command, size_t length,
                            uint8_t response[258]);

#endif
