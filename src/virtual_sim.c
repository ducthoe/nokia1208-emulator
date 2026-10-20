/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#include "virtual_sim.h"

#include <string.h>

static VirtualSimFile *file(VirtualSim *sim, uint16_t id) {
    for (unsigned i = 0; i < sim->file_count; ++i)
        if (sim->files[i].id == id && sim->files[i].directory == sim->directory)
            return &sim->files[i];
    return NULL;
}

static void add_file(VirtualSim *sim, uint16_t directory, uint16_t id,
                     unsigned size, unsigned record_size, const uint8_t *data, unsigned length) {
    VirtualSimFile *f = &sim->files[sim->file_count++];
    f->id = id;
    f->directory = directory;
    f->size = size;
    f->record_size = record_size;
    memset(f->data, 0xff, sizeof(f->data));
    if (length) memcpy(f->data, data, length);
}

void virtual_sim_init(VirtualSim *sim) {
    memset(sim, 0, sizeof(*sim));
    sim->directory = sim->selected = 0x3f00;
    static const uint8_t iccid[] = {0x98,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf1};
    static const uint8_t language[] = {'e','n'};
    static const uint8_t imsi[] = {8,0x09,0x10,0x10,0,0,0,0,0x10};
    static const uint8_t administrative[] = {0,0,0,2};
    static const uint8_t services[] = {3,0,0,0,0,0,0,0};
    static const uint8_t access[] = {0,1};
    static const uint8_t location[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,1};
    static const uint8_t cipher[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,7};
    static const uint8_t period[] = {10};
    static const uint8_t phase[] = {2};
    static const uint8_t name[] = {0,'V','i','r','t','u','a','l',' ','S','I','M'};
    add_file(sim,0x3f00,0x2fe2,10,0,iccid,sizeof(iccid));
    add_file(sim,0x3f00,0x2f05,2,0,language,sizeof(language));
    add_file(sim,0x7f20,0x6f07,9,0,imsi,sizeof(imsi));
    add_file(sim,0x7f20,0x6fad,4,0,administrative,sizeof(administrative));
    add_file(sim,0x7f20,0x6f38,8,0,services,sizeof(services));
    add_file(sim,0x7f20,0x6f78,2,0,access,sizeof(access));
    add_file(sim,0x7f20,0x6f7e,11,0,location,sizeof(location));
    add_file(sim,0x7f20,0x6f20,9,0,cipher,sizeof(cipher));
    add_file(sim,0x7f20,0x6f30,24,0,NULL,0);
    add_file(sim,0x7f20,0x6f7b,12,0,NULL,0);
    add_file(sim,0x7f20,0x6f31,1,0,period,sizeof(period));
    add_file(sim,0x7f20,0x6fae,1,0,phase,sizeof(phase));
    add_file(sim,0x7f20,0x6f05,2,0,language,sizeof(language));
    add_file(sim,0x7f20,0x6f46,17,0,name,sizeof(name));
    add_file(sim,0x7f10,0x6f3a,320,32,NULL,0);
    add_file(sim,0x7f10,0x6f40,32,32,NULL,0);
    add_file(sim,0x7f10,0x6f3b,32,32,NULL,0);
}

static unsigned information(VirtualSim *sim, uint16_t id, uint8_t *out) {
    memset(out, 0, 23);
    out[4] = id >> 8;
    out[5] = id;
    if (id == 0x3f00 || id == 0x7f20 || id == 0x7f10) {
        out[6] = id == 0x3f00 ? 1 : 2;
        out[12] = 9;
        /* TS 51.011: CHV1 disabled, 1.8/3 V supply, clock stop allowed. */
        out[13] = 0xb1;
        out[14] = id == 0x3f00 ? 2 : 0;
        out[15] = id == 0x3f00 ? 2 : 12;
        out[16] = 2;
        out[18] = out[20] = 0x83;
        out[19] = out[21] = 0x8a;
        return 22;
    }
    VirtualSimFile *f = file(sim, id);
    if (!f) return 0;
    out[2] = f->size >> 8;
    out[3] = f->size;
    out[6] = 4;
    out[11] = 1;
    out[12] = 2;
    out[13] = f->record_size ? 1 : 0;
    out[14] = f->record_size;
    return 15;
}

static size_t status(uint8_t *out, size_t length, unsigned sw) {
    out[length] = sw >> 8;
    out[length + 1] = sw;
    return length + 2;
}

size_t virtual_sim_exchange(VirtualSim *sim, const uint8_t *command, size_t length,
                            uint8_t out[258]) {
    ++sim->commands;
    if (length < 5) return status(out, 0, 0x6700);
    if (command[0] != 0xa0 && command[0] != 0x00) return status(out, 0, 0x6e00);
    unsigned requested = command[4] ? command[4] : 256;
    unsigned offset = ((unsigned)command[2] << 8) | command[3];
    VirtualSimFile *f = file(sim, sim->selected);
    switch (command[1]) {
    case 0xa4: {
        if (length != 7 || command[4] != 2) return status(out, 0, 0x6700);
        uint16_t id = (uint16_t)command[5] << 8 | command[6];
        if (id == 0x3f00 || id == 0x7f20 || id == 0x7f10) sim->directory = id;
        else if (!file(sim, id)) return status(out, 0, 0x9404);
        sim->selected = id;
        sim->response_length = information(sim, id, sim->response);
        return status(out, 0, 0x9f00 | sim->response_length);
    }
    case 0xc0:
        if (requested > sim->response_length) requested = sim->response_length;
        memcpy(out, sim->response, requested);
        return status(out, requested, 0x9000);
    case 0xf2: {
        unsigned count = information(sim, sim->directory, out);
        if (count > requested) count = requested;
        return status(out, count, 0x9000);
    }
    case 0xb0:
        if (!f || f->record_size) return status(out, 0, 0x9408);
        if (offset + requested > f->size) return status(out, 0, 0x9402);
        memcpy(out, f->data + offset, requested);
        return status(out, requested, 0x9000);
    case 0xb2:
        if (!f || !f->record_size) return status(out, 0, 0x9408);
        offset = command[2] ? (command[2] - 1u) * f->record_size : 0;
        if (requested != f->record_size || offset + requested > f->size)
            return status(out, 0, 0x9402);
        memcpy(out, f->data + offset, requested);
        return status(out, requested, 0x9000);
    case 0xd6:
        if (!f || f->record_size) return status(out, 0, 0x9408);
        if (length != requested + 5 || offset + requested > f->size)
            return status(out, 0, 0x9402);
        memcpy(f->data + offset, command + 5, requested);
        return status(out, 0, 0x9000);
    case 0xdc:
        if (!f || !f->record_size) return status(out, 0, 0x9408);
        offset = command[2] ? (command[2] - 1u) * f->record_size : 0;
        if (length != requested + 5 || requested != f->record_size || offset + requested > f->size)
            return status(out, 0, 0x9402);
        memcpy(f->data + offset, command + 5, requested);
        return status(out, 0, 0x9000);
    case 0x20: case 0x26: case 0x28:
        return status(out, 0, 0x9808);
    case 0x88:
        return status(out, 0, 0x9804); /* No subscriber authentication key. */
    default:
        return status(out, 0, 0x6d00);
    }
}
