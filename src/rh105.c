/* SPDX-FileCopyrightText: 2026 ducthoe
 * SPDX-License-Identifier: GPL-3.0-only */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <mgba/internal/arm/arm.h>
#include <mgba/internal/arm/isa-inlines.h>

#include "tds6_safer.h"
#include "virtual_sim.h"
#include "nvram.h"

#define FLASH_BASE 0x01000000u
#define FLASH_SIZE 0x01000000u
/* Firmware globals reach 0x000e92b8; physical RAM banking remains unresolved. */
#define RAM_SIZE 0x00100000u
#define HEADER_RAM_BASE 0x007FE000u
#define HEADER_RAM_SIZE 0x2000u
#define ADDRESS_SPACE 0x10000000u
#define CTSI_BASE 0x06010000u
#define MCUPLL_BASE 0x06009000u
#define DSPPLL_BASE 0x06008000u
#define UIF_BASE 0x06010400u
#define AUDIO_RATE 44100u
#define DAC_RATE 40000u
#define BUZZER_ENABLE 0x4000u
#define BUZZER_DIVIDER 0x3FFFu
#define SIMIF_BASE 0x06010800u
#define BRAIN_BASE 0x06100000u
#define HISTORY 32u
#define KEY_INPUT_CAPACITY 256u
#define KEY_EDGE_TICKS (32768u / 20u) /* 50 ms: at least one debounced firmware scan. */

static volatile sig_atomic_t stop_requested;
static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

typedef struct { uint32_t base, size; } RegisterRange;
typedef struct { uint32_t pc, address, value; unsigned width, write; } BusEvent;
static const RegisterRange register_ranges[] = {
    {0x05100000, 0x100},
    {0x06002000, 0x100}, {0x06008000, 0x100}, {0x06009000, 0x100},
    {0x0600A000, 0x100}, {0x0600B000, 0x100}, {0x0600C000, 0x100},
    {0x0600C800, 0x100}, {0x0600D000, 0x100}, {0x0600F000, 0x100},
    {0x06010000, 0x300}, {0x06010400, 0x200}, {0x06010800, 0x200},
    {0x06100000, 0x100},
};

typedef struct {
    struct ARMCore cpu;
    uint8_t *memory;
    jmp_buf stop;
    const char *reason;
    const char *operation;
    uint32_t address;
    uint32_t value;
    unsigned width;
    uint64_t steps;
    uint32_t pc;
    uint32_t fetch_base, fetch_size;
    uint32_t history[HISTORY];
    unsigned states[HISTORY];
    uint32_t opcodes[HISTORY];
    uint16_t pll_control;
    uint16_t ctsi_control;
    /* CTSI+0x0000: powerup reason in bits 0-4, plus the "command complete"
       handshake bit 9 that the firmware's wait loops poll after writing
       0x10 to CTSI+0x0024 (see rh105.c:1160 region / 0x011edc40). */
    uint16_t ctsi_states;
    unsigned ctsi_state_written;
    unsigned pll_written;
    uint16_t dsp_pll_control;
    unsigned dsp_pll_written;
    unsigned ctsi_written;
    uint64_t mmio_count;
    BusEvent mmio_history[HISTORY];
    uint8_t register_written[0x100200];
    unsigned legacy_reset_state;
    /* Reading a peripheral register that firmware has not yet written used to
       stop the emulator outright.  Boot-time peripheral enumeration reads many
       registers whose reset value is not modelled, so the default is now to
       report the address once and read zero -- the behaviour of the reference
       implementation (TriX_HWemu `hwemu_default_handle`).  Set
       RH105_STRICT_REGISTERS=1 to stop on them again. */
    unsigned strict_registers;
    unsigned unknown_register_traces;
    uint16_t system_type;
    char debug_text[4096];
    size_t debug_length;
    uint16_t cbus_command;
    uint16_t cbus_length;
    uint16_t cbus_high;
    uint16_t cbus_low;
    uint32_t cbus_registers[8][32];
    unsigned cbus_transfers;
    uint16_t adc_result;
    /* UEM buzzer -- CBUS device 1 register 0x18, driven by firmware
       `hw_buzz.c` at 0x01145104 (bit 0x4000 = enable, bits 0..13 = divider). */
    uint16_t buzzer_divider;
    unsigned buzzer_enable;
    uint16_t buzzer_test;
    unsigned buzzer_test_divider;
    double audio_phase;
    FILE *audio_out;
    uint64_t audio_last_tick;
    uint64_t audio_frac;
    unsigned audio_started;
    uint32_t audio_samples;
    uint32_t dac_position, dac_resample;
    uint64_t dac_samples, dac_nonzero_samples;
    int16_t dac_value, dac_previous;
    unsigned dac_primed;
    uint8_t audio_buffer[1024];
    size_t audio_pending;
    unsigned cbus_log_limit;
    uint64_t clock_ticks_q32;
    uint64_t clock_step_q32;
    uint64_t events_tick;
    uint64_t realtime_epoch_ns, realtime_next_tick;
    unsigned realtime;
    int32_t clock_last_cycles;
    uint16_t timer2_prescaler;
    uint64_t timer2_epoch;
    unsigned flash_mode;
    unsigned flash_pending;
    unsigned flash_busy;
    uint32_t flash_command_address;
    uint16_t flash_configuration;
    unsigned raw_flash_loaded;
    uint32_t rom_size;
    unsigned rom_hle;
    unsigned rom_copy_calls;
    unsigned tds6_safer;
    unsigned tds6_zero_key_profile;
    unsigned rom_decode_calls;
    unsigned rom_encode_calls;
    Tds6SaferProfile safer_profile;
    uint32_t last_cipher_data;
    uint32_t last_cipher_length;
    uint8_t last_cipher_mode;
    uint8_t last_cipher_output[40];
    uint32_t rom_flash_limits[4];
    unsigned rom_flash_limit_calls;
    unsigned rom_fsig_calls;
    unsigned flash_programs;
    NvramStore nvram;
    unsigned nvram_dirty;
    uint64_t nvram_next_save;
    unsigned flash_erases;
    unsigned flash_commands;
    uint64_t power_key_release_tick;
    uint32_t rom_status_flags;
    unsigned rom_status_calls;
    unsigned lcd_commands;
    unsigned lcd_data_bytes;
    FILE *lcd_trace;
    unsigned lcd_trace_dirty;
    uint16_t gpio_output[3];
    uint8_t lcd_command;
    unsigned lcd_read_phase;
    uint8_t lcd_id[3];
    uint16_t irq_enabled[7];
    uint16_t irq_pending[7];
    unsigned irq_blocked;
    unsigned fiq_blocked;
    unsigned irq_deliveries;
    unsigned fiq_deliveries;
    uint16_t timer2_base;
    uint16_t timer2_compare;
    uint64_t timer2_value_epoch;
    uint64_t timer2_deadline;
    unsigned timer2_armed;
    unsigned timer2_matches;
    uint16_t call_timer_divider;
    unsigned call_timer_enabled;
    uint64_t call_timer_period_q32, call_timer_deadline_q32, call_timer_ticks;
    unsigned timer_register_writes;
    unsigned mdi_peer;
    unsigned mdi_registration_sent;
    unsigned mdi_tx_words;
    unsigned mdi_tx_batches;
    uint64_t mdi_next_announcement;
    unsigned mdi_announcements;
    uint8_t mdi_tx_packet[4096];
    unsigned mdi_tx_length;
    unsigned mdi_unavailable_replies;
    uint64_t timer2_coarse_slot;
    unsigned timer2_coarse_events;
    char virtual_imei[16];
    uint16_t uem_otp[4];
    unsigned mdi_mtc_ready;
    unsigned mdi_mtc_responses;
    unsigned mdi_version_replies;
    unsigned sim_detect_high;
    uint16_t sim_control;
    uint16_t sim_status;
    unsigned sim_rx_waiting;
    uint64_t sim_rx_deadline;
    unsigned sim_rx_timeouts;
    unsigned virtual_sim_enabled;
    VirtualSim virtual_sim;
    unsigned sim_atr_started, sim_card_ready, sim_rx_armed, sim_transfer_count, sim_tx_count;
    uint8_t sim_command[261], sim_reply[259];
    unsigned sim_command_length, sim_reply_length, sim_reply_position;
    uint64_t sim_reply_ready;
    unsigned comm_call_traces;
    unsigned dsp_call_traces;
    unsigned ui_call_traces;
    unsigned sim_bus_traces;
    unsigned pn_resource_traces[256];
    unsigned graph_control_traces;
    unsigned dma_lcd_ready[2];
    uint64_t dma_lcd_deadline[2];
    uint64_t dma_lcd_start[2], dma_lcd_next_chunk[2];
    unsigned dma_lcd_progress[2];
    uint32_t lcd_serial_hz;
    unsigned trace_lcd_timing;
    uint64_t dma_lcd_bytes;
    unsigned dma_completions[2];
    uint16_t uif_direction[2];
    uint8_t uif_irq_mask[2];
    uint32_t keypad_pressed;
    uint64_t keypad_release[21];
    unsigned keypad_changes;
    unsigned stdin_keys;
    uint64_t key_input_next_poll;
    char key_input_buffer[256];
    unsigned key_input_length;
    unsigned key_input_overflow;
    struct { unsigned key, state; } key_commands[KEY_INPUT_CAPACITY];
    unsigned key_command_head, key_command_count;
    uint64_t keypad_next_edge[21];
    unsigned trace_keypad, trace_scan, trace_uif, trace_ram, trace_pc, trace_progress;
    unsigned no_history;
    uint64_t progress_next;
    struct { uint32_t address, value; } pokes[8];
    unsigned poke_count;
} Machine;

static Machine *owner(struct ARMCore *cpu) { return (Machine *)cpu; }
static void stop_at(Machine *m, const char *reason, const char *operation,
                    uint32_t address, unsigned width, uint32_t value);

static uint64_t monotonic_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static void realtime_pace(Machine *m) {
    uint64_t ticks = m->clock_ticks_q32 >> 32;
    if (ticks < m->realtime_next_tick) return;
    m->realtime_next_tick = ticks + 328; /* About 10 ms between host clock reads. */
    uint64_t target = m->realtime_epoch_ns + ticks / 32768 * 1000000000 +
                      ticks % 32768 * 1000000000 / 32768;
    uint64_t now = monotonic_ns();
    if (target > now) {
        uint64_t delay = target - now;
        struct timespec remaining = {.tv_sec = (time_t)(delay / 1000000000),
                                     .tv_nsec = (long)(delay % 1000000000)};
        while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    }
}

static void clock_sync(Machine *m) {
    int32_t delta = m->cpu.cycles - m->clock_last_cycles;
    if (delta > 0) m->clock_ticks_q32 += (uint64_t)delta * m->clock_step_q32;
    m->clock_last_cycles = m->cpu.cycles;
}

static void call_timer_arm(Machine *m) {
    clock_sync(m);
    m->call_timer_period_q32 = (uint64_t)(m->call_timer_divider + 1) * 12 *
                              ((32768ull << 32) / 13000000);
    m->call_timer_deadline_q32 = m->clock_ticks_q32 + m->call_timer_period_q32;
}

static void sim_poll(Machine *m) {
    if (m->virtual_sim_enabled && m->sim_rx_armed &&
        m->sim_reply_length - m->sim_reply_position >= m->sim_transfer_count &&
        (m->clock_ticks_q32 >> 32) >= m->sim_reply_ready) {
        m->sim_status |= 0x10;
        m->sim_rx_armed = m->sim_rx_waiting = 0;
    }
}

static void sim_transmit(Machine *m, uint8_t value) {
    if (!m->sim_atr_started) return;
    m->sim_rx_armed = 0;
    if (m->sim_command_length < sizeof(m->sim_command))
        m->sim_command[m->sim_command_length++] = value;
    if (++m->sim_tx_count < m->sim_transfer_count) return;
    m->sim_status |= 8;
    clock_sync(m);
    fprintf(stderr, "[virtual-sim] tx:");
    for (unsigned i = 0; i < m->sim_command_length; ++i)
        fprintf(stderr, " %02x", m->sim_command[i]);
    fputc('\n', stderr);
    unsigned wanted = 5;
    if (m->sim_command_length >= 5) {
        unsigned ins = m->sim_command[1];
        if (ins == 0xa4 || ins == 0xd6 || ins == 0xdc || ins == 0x20 || ins == 0x88)
            wanted += m->sim_command[4];
    }
    if (m->sim_command_length >= wanted) {
        m->sim_reply_length = virtual_sim_exchange(&m->virtual_sim, m->sim_command,
                                                   m->sim_command_length, m->sim_reply);
        if (m->sim_reply_length > 2) {
            memmove(m->sim_reply + 1, m->sim_reply, m->sim_reply_length);
            m->sim_reply[0] = m->sim_command[1];
            ++m->sim_reply_length;
        }
        m->sim_reply_position = 0;
        m->sim_command_length = 0;
        m->sim_reply_ready = (m->clock_ticks_q32 >> 32) + 33;
        fprintf(stderr, "[virtual-sim] response bytes=%u status=%02x%02x\n", m->sim_reply_length,
                m->sim_reply[m->sim_reply_length - 2], m->sim_reply[m->sim_reply_length - 1]);
    } else if (m->sim_command_length == 5) {
        m->sim_reply[0] = m->sim_command[1]; /* T=0 procedure byte: send the command body. */
        m->sim_reply_length = 1;
        m->sim_reply_position = 0;
        m->sim_reply_ready = (m->clock_ticks_q32 >> 32) + 33;
    }
    m->cpu.nextEvent = m->cpu.cycles;
}

static uint64_t timer2_ticks(Machine *m) {
    clock_sync(m);
    return (m->clock_ticks_q32 >> 32) - m->timer2_epoch;
}

static uint16_t timer2_value(Machine *m) {
    clock_sync(m);
    return (uint16_t)(m->timer2_base + ((m->clock_ticks_q32 >> 32) - m->timer2_value_epoch) /
                     ((m->timer2_prescaler & 0x1Fu) + 1u));
}

static void timer2_arm(Machine *m) {
    uint16_t current = timer2_value(m);
    uint32_t distance = (uint16_t)(m->timer2_compare - current);
    m->timer2_deadline = (m->clock_ticks_q32 >> 32) +
                         (uint64_t)distance * ((m->timer2_prescaler & 0x1Fu) + 1u);
    m->timer2_armed = 1;
    m->cpu.nextEvent = m->cpu.cycles;
}

static int irq_register(uint32_t address, unsigned width, unsigned *group, unsigned *kind) {
    static const uint16_t pending[7] = {0xB8, 0xBA, 0x100, 0x102, 0x104, 0x106, 0x108};
    static const uint16_t disable[7] = {8, 12, 16, 20, 24, 28, 32};
    if (width != 2) return 0;
    for (unsigned i = 0; i < 7; ++i) {
        if (address == CTSI_BASE + pending[i]) { *group = i; *kind = 0; return 1; }
        if (address == CTSI_BASE + disable[i]) { *group = i; *kind = 1; return 1; }
        if (address == CTSI_BASE + disable[i] + 2u) { *group = i; *kind = 2; return 1; }
    }
    return 0;
}

static uint16_t flash_word(Machine *m, uint32_t address) {
    if (m->flash_mode == 1) {
        if (m->flash_busy) { --m->flash_busy; return 0; }
        return 0x80;
    }
    unsigned offset = (address & 0xFFFF) >> 1;
    if (m->flash_mode == 2) {
        if (offset == 0) return 0x0089;
        if (offset == 1) return 0x8872;
        if (offset == 5) return m->flash_configuration;
        return 0;
    }
    if (m->flash_mode == 3) {
        switch (offset) {
            case 0x10: return 'Q'; case 0x11: return 'R'; case 0x12: return 'Y';
            case 0x13: return 1; case 0x15: return 0x40;
            case 0x1B: return 0x27; case 0x1C: return 0x36;
            case 0x1F: return 4; case 0x20: return 4; case 0x21: return 10;
            case 0x23: return 4; case 0x24: return 4; case 0x25: return 4;
            case 0x27: return 24; case 0x28: return 2; case 0x2A: return 5;
            case 0x2C: return 1; case 0x2D: return 255; case 0x30: return 1;
            case 0x40: return 'P'; case 0x41: return 'R'; case 0x42: return 'I';
            case 0x43: return '1'; case 0x44: return '3';
            case 0x5D: return 3;
            default: return 0;
        }
    }
    return ((uint16_t)m->memory[address] << 8) | m->memory[address + 1];
}

static int flash_special_read(const Machine *m, uint32_t address) {
    /* NOR status/ID commands affect their partition. IRQ code and literals
       in other partitions must remain readable during PMM programming. */
    return m->flash_mode && !((address ^ m->flash_command_address) & 0xfff80000u);
}

static int unencrypted_flash(const Machine *m, uint32_t address, unsigned width) {
    for (unsigned i = 0; i < 4; i += 2) {
        uint32_t start = m->rom_flash_limits[i], end = m->rom_flash_limits[i + 1];
        if (end > start && address >= start && (uint64_t)address + width <= end) return 1;
    }
    return 0;
}

static void flash_write(Machine *m, uint32_t address, unsigned width, uint32_t value) {
    if (width != 2) stop_at(m, "unsupported_flash_write_width", "write", address, width, value);
    if (m->flash_pending == 1) {
        if (!unencrypted_flash(m, address, width))
            stop_at(m, "encrypted_flash_program_unimplemented", "write", address, width, value);
        m->memory[address] &= value >> 8;
        m->memory[address + 1] &= value;
        if (address >= NVRAM_BASE) m->nvram_dirty = 1;
        if (m->raw_flash_loaded) {
            m->memory[address + 0x08000000] &= value >> 8;
            m->memory[address + 0x08000001] &= value;
        }
        if (m->flash_programs++ < 16)
            fprintf(stderr, "[flash] program address=%08x value=%04x pc=%08x\n", address, value, m->pc);
        m->flash_pending = 0;
        m->flash_mode = 1;
        m->flash_busy = 2;
        return;
    }
    if (m->flash_pending == 2 && value == 0xD0) {
        memset(m->memory + (address & ~0xFFFFu), 0xFF, 0x10000);
        if (m->raw_flash_loaded)
            memset(m->memory + ((address + 0x08000000) & ~0xFFFFu), 0xFF, 0x10000);
        ++m->flash_erases;
        if (address >= NVRAM_BASE) m->nvram_dirty = 1;
        m->flash_pending = 0;
        m->flash_mode = 1;
        m->flash_busy = 2;
        return;
    }
    if (m->flash_pending == 3) {
        m->flash_pending = 0;
        m->flash_mode = 0;
        return;
    }
    m->flash_command_address = address;
    switch (value & 255) {
        case 0xFF: case 0xF0: m->flash_mode = 0; m->flash_pending = 0; break;
        case 0x90: m->flash_mode = 2; break;
        case 0x98: m->flash_mode = 3; break;
        case 0x70: m->flash_mode = 1; break;
        case 0x50: m->flash_busy = 0; break;
        case 0x40: case 0x10: m->flash_pending = 1; break;
        case 0x20: m->flash_pending = 2; break;
        case 0x60: m->flash_pending = 3; break;
        case 0xB8: m->flash_configuration = address & 0xFFFF; m->flash_pending = 3; break;
        case 0xD0: m->flash_mode = 1; break;
        default: stop_at(m, "unimplemented_flash_command", "write", address, width, value);
    }
    if (m->flash_commands++ < 128)
        fprintf(stderr, "[flash] command=%02x address=%08x pc=%08x\n", value & 255, address, m->pc);
}

static void stop_at(Machine *m, const char *reason, const char *operation,
                    uint32_t address, unsigned width, uint32_t value) {
    m->reason = reason;
    m->operation = operation;
    m->address = address;
    m->width = width;
    m->value = value;
    longjmp(m->stop, 1);
}

static int in_range(uint32_t address, unsigned width, uint32_t base, uint32_t size) {
    return address >= base && (uint64_t)address + width <= (uint64_t)base + size;
}

static int plain_memory(const Machine *m, uint32_t address, unsigned width) {
    return in_range(address, width, 0, RAM_SIZE) ||
           in_range(address, width, HEADER_RAM_BASE, HEADER_RAM_SIZE) ||
           (m->rom_size && in_range(address, width, 0x00800000, m->rom_size)) ||
           (m->rom_hle && in_range(address, width, 0x00840000, 0x48)) ||
           in_range(address, width, 0x05000000, 0x00100000) ||
           in_range(address, width, 0x07000000, 0x2000) ||
           in_range(address, width, FLASH_BASE, FLASH_SIZE);
}

static int register_memory(uint32_t address, unsigned width) {
    for (unsigned i = 0; i < sizeof(register_ranges) / sizeof(register_ranges[0]); ++i)
        if (in_range(address, width, register_ranges[i].base, register_ranges[i].size))
            return 1;
    return 0;
}

static uint32_t register_index(uint32_t address) {
    if (address >= 0x05100000 && address < 0x05100100)
        return 0x100100 + address - 0x05100000;
    return address - 0x06000000;
}

static void mmio_log(Machine *m, const char *operation, uint32_t address,
                     unsigned width, uint32_t value) {
    m->mmio_history[m->mmio_count % HISTORY] =
        (BusEvent){m->pc, address, value, width, !strcmp(operation, "write")};
    if (m->mmio_count++ < 64)
        fprintf(stderr, "%08" PRIx32 " %s%u [%08" PRIx32 "] %08" PRIx32 "\n",
                m->pc, operation, width * 8, address, value);
}

static uint32_t cbus_read(Machine *m, unsigned device, unsigned reg) {
    uint32_t value = m->cbus_registers[device][reg];
    if (device == 1 && reg == 0) value = 0x0A10;
    if (device == 1 && reg >= 0x1B && reg <= 0x1E) value = m->uem_otp[reg - 0x1B];
    if (device == 1 && reg == 0x1A) value = m->adc_result;
    if (device == 1 && reg == 0x1F) {
        clock_sync(m);
        /* UEM PWRKEY bit is high while pressed. 011f2702 inverts it into
           the keypad scanner's released-high bitmap. */
        value = (m->clock_ticks_q32 >> 32) < m->power_key_release_tick ||
                (m->keypad_pressed & (1u << 20)) ? 2 : 0;
        if (m->sim_detect_high) value |= 4;
    }
    if (m->cbus_transfers++ < 256)
        fprintf(stderr, "[cbus] read device=%u register=%02x bits=%u value=%08x pc=%08x\n",
                device, reg, m->cbus_length & 31, value, m->pc);
    return value;
}

static void cbus_write(Machine *m, unsigned device, unsigned reg, uint32_t value) {
    uint32_t previous = m->cbus_registers[device][reg];
    if (device == 1 && reg == 0x15) m->cbus_registers[device][reg] &= ~value;
    else m->cbus_registers[device][reg] = value;
    if (m->virtual_sim_enabled && device == 1 && reg == 8) {
        /* UEM SIM-clock state: bit 2 reports the running clock. */
        m->cbus_registers[1][8] = value & 0x88 ? value | 4 : value & ~4u;
        m->cpu.nextEvent = m->cpu.cycles;
    }
    if (m->virtual_sim_enabled && device == 1 && reg == 0x16 &&
        m->sim_card_ready && (previous & 0x80) && !(value & 0x80)) {
        /* The driver masks then unmasks this readiness request before TX. */
        m->cbus_registers[1][8] |= 4;
        m->cbus_registers[1][0x15] |= 0x80;
        m->cpu.nextEvent = m->cpu.cycles;
    }
    if (device == 1 && reg == 0x18) {
        /* Firmware `hw_buzz.c` driver 0x01145104: it writes the full 16-bit
           register with the divider in bits 0..13 (0x01145188, mask 0xFFFF),
           then sets bit 0x4000 to start the tone (0x01145194, mask 0x4000) and
           clears 0x4000 to stop it (0x0114519e). */
        m->buzzer_divider = value & BUZZER_DIVIDER;
        m->buzzer_enable = (value & BUZZER_ENABLE) != 0;
        fprintf(stderr, "[buzzer] %s divider=%u tick=%" PRIu64 " pc=%08x\n",
                m->buzzer_enable ? "on " : "off", m->buzzer_divider,
                m->clock_ticks_q32 >> 32, m->pc);
    }
    if (device == 1 && reg == 0x19 && (value & 0x0800)) {
        static const uint16_t samples[16] = {
            0x1F9, 0x3EC, 0x1E6, 0x3E8, 0x2B8, 0x3F0, 0, 0x3F3,
            0x303, 0, 0, 0x37B, 0x397, 0x3F5, 0, 0
        };
        m->adc_result = samples[(value >> 12) & 15];
        m->cbus_registers[device][reg] &= ~0x0800u;
    }
    if (m->cbus_transfers++ < m->cbus_log_limit)
        fprintf(stderr, "[cbus] write device=%u register=%02x bits=%u value=%08x pc=%08x\n",
                device, reg, m->cbus_length & 31, value, m->pc);
}

static uint16_t gpio_input(Machine *m, unsigned port) {
    uint16_t value = m->gpio_output[port];
    uint16_t test_enable = (uint16_t)m->memory[0x0600F00C] << 8 | m->memory[0x0600F00D];
    if (port == 0) {
        if ((test_enable & 3) == 3) {
            value &= ~2u;
            /* UEM EAR_DATA route: audio loop selection and input buffer. */
            if (!(m->cbus_registers[1][0x17] & 0x3C00) &&
                (m->cbus_registers[1][0x0A] & 8) && (m->cbus_registers[1][0x1C] & 0x80))
                value |= (m->gpio_output[0] & 1) << 1;
        }
        if ((test_enable & 0x0300) == 0x0300) {
            value &= ~0x0200u;
            if (m->cbus_registers[1][0x0C] & 0x20)
                value |= (m->gpio_output[0] & 0x0100) << 1;
        }
    } else if (port == 1) {
        uint16_t sim_override = (uint16_t)m->memory[0x0600F00E] << 8 | m->memory[0x0600F00F];
        if ((sim_override & 7) == 7) {
            value &= ~2u;
            if ((m->cbus_registers[1][0x0C] & 0x20) && (m->gpio_output[1] & 4))
                value |= (m->gpio_output[1] & 1) << 1;
        }
    }
    return value;
}

static uint16_t memory16(const Machine *m, uint32_t address) {
    return (uint16_t)m->memory[address] << 8 | m->memory[address + 1];
}

static void memory16_set(Machine *m, uint32_t address, uint16_t value) {
    m->memory[address] = value >> 8;
    m->memory[address + 1] = (uint8_t)value;
}

static uint32_t memory32(const Machine *m, uint32_t address) {
    return (uint32_t)memory16(m, address) << 16 | memory16(m, address + 2);
}

static uint16_t keypad_columns(const Machine *m) {
    /* Matrix model derived from the scan routine at 0x011f2716.
       The outer loop drives IO D direction with 0x0002/0x0004/0x0008/0x0010
       (one column at a time, column = bit position - 1) while IO D data holds
       bits 1..4 low; IO E bits 0..4 then read the five rows back active-low.
       The scanner builds its key bitmap as `1 << (4*row + column)` -- see
       `adds r7,r2,r6` / `lsls r3,r7` at 0x011f276e, where r2 counts 4 per row
       and r6 counts 1 per column pass. */
    uint16_t columns = 0x1F;
    uint16_t outputs = memory16(m, UIF_BASE);
    for (unsigned key = 0; key < 20; ++key) {
        unsigned row = key / 4;          /* IO E bit, 0..4 */
        unsigned column = key % 4;       /* IO D direction bit, 1..4 */
        if (!(m->keypad_pressed & (1u << key))) continue;
        if (!(m->uif_direction[0] & (1u << (column + 1)))) continue;  /* column driven */
        if (outputs & (1u << (column + 1))) continue;                 /* column low */
        columns &= ~(1u << row);
    }
    return columns;
}

static void keypad_set(Machine *m, unsigned key, unsigned pressed) {
    if (key >= 21) return;
    uint32_t mask = 1u << key;
    if (!!(m->keypad_pressed & mask) == !!pressed) return;
    uint16_t before = keypad_columns(m);
    if (pressed) m->keypad_pressed |= mask;
    else m->keypad_pressed &= ~mask;
    if (key == 20) {
        m->cbus_registers[1][0x15] |= 0x0200;
    } else if ((before ^ keypad_columns(m)) & (uint8_t)~m->uif_irq_mask[1] & 0x1F) {
        m->irq_pending[2] |= 4;
    }
    ++m->keypad_changes;
    if (m->trace_lcd_timing)
        fprintf(stderr, "[timing] key=%u state=%u tick=%" PRIu64 " wall_ns=%" PRIu64 "\n",
                key, pressed, m->clock_ticks_q32 >> 32, monotonic_ns());
    m->keypad_next_edge[key] = (m->clock_ticks_q32 >> 32) + KEY_EDGE_TICKS;
    fprintf(stderr, "[keypad] matrix=%u state=%s\n", key, pressed ? "down" : "up");
    if (m->trace_keypad)
        fprintf(stderr, "[keypad-lines] d=%02x e=%02x mask=%02x pending=%04x enabled=%04x tick=%" PRIu64 "\n",
                m->uif_direction[0], keypad_columns(m), m->uif_irq_mask[1],
                m->irq_pending[2], m->irq_enabled[2], m->clock_ticks_q32 >> 32);
    m->cpu.nextEvent = m->cpu.cycles;
}

/* Decimal stdin protocol: exactly two bounded integers, or "quit". */
static int keypad_parse(const char *text, unsigned *key, unsigned *state) {
    char *end;
    if (*text < '0' || *text > '9') return 0;
    errno = 0;
    unsigned long k = strtoul(text, &end, 10);
    if (errno || k >= 21 || (*end != ' ' && *end != '\t')) return 0;
    while (*end == ' ' || *end == '\t') ++end;
    text = end;
    if (*text < '0' || *text > '9') return 0;
    unsigned long s = strtoul(text, &end, 10);
    if (errno || s > 2) return 0;
    while (*end == ' ' || *end == '\t' || *end == '\r') ++end;
    if (*end) return 0;
    *key = (unsigned)k;
    *state = (unsigned)s;
    return 1;
}

static void keypad_queue(Machine *m, unsigned key, unsigned state) {
    if (m->key_command_count == KEY_INPUT_CAPACITY)
        stop_at(m, "key_input_queue_full", "input", 0, 0, 0);
    unsigned tail = (m->key_command_head + m->key_command_count++) % KEY_INPUT_CAPACITY;
    m->key_commands[tail].key = key;
    m->key_commands[tail].state = state;
}

static void keypad_deliver(Machine *m, uint64_t now) {
    while (m->key_command_count) {
        unsigned head = m->key_command_head;
        unsigned key = m->key_commands[head].key, state = m->key_commands[head].state;
        int held = !!(m->keypad_pressed & (1u << key));
        /* A press and release may arrive in the same host read. Do not
           erase that pulse (or a quick subsequent tap) before a guest scan.
           Preserve order and minimum dwell on both sides of a real edge. */
        if (held != (state != 0) && now < m->keypad_next_edge[key]) break;
        keypad_set(m, key, state != 0);
        m->keypad_release[key] = state == 2 ? now + 32768 / 5 : 0;
        m->key_command_head = (head + 1) % KEY_INPUT_CAPACITY;
        --m->key_command_count;
    }
}

static void keypad_poll(Machine *m) {
    uint64_t now = m->clock_ticks_q32 >> 32;
    /* Deterministic key injection: RH105_KEY_SCRIPT="tick:key:state,..."
       e.g. "15695:5:1,16000:5:0" presses matrix key 5 at emulated tick 15695.
       State 0=release, 1=press, 2=auto-release after 200 ms. */
    static struct { uint64_t tick; unsigned key, state; int done; } script[64];
    static unsigned script_count, script_init;
    if (!script_init) {
        script_init = 1;
        const char *text = getenv("RH105_KEY_SCRIPT");
        while (text && *text && script_count < sizeof(script) / sizeof(script[0])) {
            unsigned long long tick;
            unsigned key, state;
            if (sscanf(text, "%llu:%u:%u", &tick, &key, &state) != 3) break;
            if (key < 21 && state <= 2) {
                script[script_count].tick = tick;
                script[script_count].key = key;
                script[script_count].state = state;
                ++script_count;
            }
            const char *comma = strchr(text, ',');
            if (!comma) break;
            text = comma + 1;
        }
    }
    for (unsigned i = 0; i < script_count; ++i) {
        if (script[i].done || now < script[i].tick) continue;
        script[i].done = 1;
        keypad_set(m, script[i].key, script[i].state != 0);
        m->keypad_release[script[i].key] = script[i].state == 2 ? now + 32768 / 5 : 0;
    }
    for (unsigned key = 0; key < 21; ++key) {
        if (m->keypad_release[key] && now >= m->keypad_release[key]) {
            m->keypad_release[key] = 0;
            keypad_set(m, key, 0);
        }
    }
    keypad_deliver(m, now);
    if (!m->stdin_keys || now < m->key_input_next_poll) return;
    m->key_input_next_poll = now + 33;
    struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
    if (poll(&input, 1, 0) <= 0 || !(input.revents & (POLLIN | POLLHUP))) return;
    char bytes[256];
    ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
    if (count <= 0) { m->stdin_keys = 0; return; }
    for (ssize_t i = 0; i < count; ++i) {
        if (bytes[i] == '\n') {
            m->key_input_buffer[m->key_input_length] = 0;
            unsigned key, state;
            if (m->key_input_overflow) {
                /* Never execute the valid-looking prefix of an oversized line. */
            } else if (keypad_parse(m->key_input_buffer, &key, &state)) {
                keypad_queue(m, key, state);
            } else if (!strcmp(m->key_input_buffer, "quit")) {
                stop_at(m, "user_exit", "input", 0, 0, 0);
            }
            m->key_input_length = 0;
            m->key_input_overflow = 0;
        } else if (!bytes[i] || m->key_input_length + 1 >= sizeof(m->key_input_buffer)) {
            m->key_input_overflow = 1;
        } else if (!m->key_input_overflow) {
            m->key_input_buffer[m->key_input_length++] = bytes[i];
        }
    }
    keypad_deliver(m, now);
}

static int mdi_receive(Machine *m, const uint8_t *packet, unsigned length) {
    uint16_t write = memory16(m, 0x050003EC), read = memory16(m, 0x050003EE);
    unsigned words = (length + 1u) / 2;
    if ((read + 249u - write) % 250u < words) return 0;
    for (unsigned offset = 0; offset < length; offset += 2) {
        uint16_t value = (uint16_t)packet[offset] << 8;
        if (offset + 1 < length) value |= packet[offset + 1];
        memory16_set(m, 0x050001F4 + write * 2u, value);
        write = (uint16_t)((write + 1) % 250);
    }
    memory16_set(m, 0x050003EC, write);
    return 1;
}

static void mdi_packet(Machine *m, const uint8_t *packet, unsigned length) {
    if (length >= 8 && packet[1] == 0x7C && packet[3] == 0xD0 && packet[6] == 5 && !m->mdi_mtc_ready) {
        static const uint8_t ready[12] = {0x12, 0xFF, 0x7C, 0x15, 0, 6, 0, 0, 0, 0xC0, 1, 4};
        if (mdi_receive(m, ready, sizeof(ready))) {
            m->mdi_mtc_ready = 1;
            fprintf(stderr, "[mdi-peer] MTC normal/ready indication\n");
        }
    }
    if (length >= 10 && packet[1] == 0x7C && packet[3] == 0x15) {
        uint8_t response[12] = {0x12, packet[2], 0x7C, 0x15, 0, 6, packet[7], packet[6], packet[8], 0, 0, 0};
        if (packet[9] == 2) {
            response[9] = 0x65;
            response[10] = 1;
            response[11] = 1;
        } else if (packet[9] == 0x0B) {
            response[9] = 0x6E;
        } else if (packet[9] == 1) {
            response[9] = 0x64;
            response[10] = length > 10 && packet[10] == 1 ? 0 : 0x14;
        } else return;
        if (mdi_receive(m, response, sizeof(response))) ++m->mdi_mtc_responses;
        return;
    }
    if (length >= 11 && packet[1] == 0x7C && packet[3] == 0xF1 && packet[9] == 0xA0 &&
        ((packet[8] == 0x20 && packet[10] == 2) || (packet[8] == 0x40 && packet[10] == 1))) {
        /* LOC's reply handler at 0x0111B4DE reads a byte count followed by
           version data. This peer has no recovered DSP version to report. */
        uint8_t response[12] = {0x12, packet[2], 0x7C, 0xF1, 0, 6,
                                packet[7], packet[6], packet[8], 0xA1, 0, 0};
        if (mdi_receive(m, response, sizeof(response))) {
            ++m->mdi_version_replies;
            fprintf(stderr, "[mdi-peer] DSP version response transaction=%02x bytes=0\n", packet[8]);
        }
        return;
    }
    if (length < 10 || packet[1] != 0x7C || packet[3] < 0xF0 || packet[3] > 0xF3 ||
        packet[9] == 0xF0) return;
    /* Match the firmware's common entity-unavailable response builder at
       0x011382B2. Unimplemented services do not report successful results. */
    uint8_t response[16] = {0x12, packet[2], packet[1], packet[3], 0, 10,
                            packet[7], packet[6], packet[8], 0xF0, 0x14, packet[9], 0, 0, 0, 0};
    if (mdi_receive(m, response, sizeof(response))) {
        if (m->mdi_unavailable_replies++ < 16)
            fprintf(stderr, "[mdi-peer] entity unavailable resource=%02x message=%02x\n", packet[3], packet[9]);
    }
}

static void mdi_poll(Machine *m) {
    if (!m->mdi_peer || !(memory16(m, 0x05100002) & 1)) return;
    uint16_t tx_write = memory16(m, 0x050003E8), tx_read = memory16(m, 0x050003EA);
    uint16_t rx_write = memory16(m, 0x050003EC), rx_read = memory16(m, 0x050003EE);
    if (tx_write >= 250 || tx_read >= 250 || rx_write >= 250 || rx_read >= 250)
        stop_at(m, "invalid_mdi_ring_index", "mdi", 0x050003E8, 2, tx_write);
    uint64_t now = m->clock_ticks_q32 >> 32;
    if (now >= m->mdi_next_announcement && (m->irq_enabled[2] & 0x0400) && rx_write == rx_read) {
        /* Reserved internal device 7C announces itself through the D0
           registration service (command 4), on MDI medium 12. */
        static const uint8_t registration[8] = {0x12, 0, 0x7C, 0xD0, 0, 2, 4, 0};
        mdi_receive(m, registration, sizeof(registration));
        m->mdi_registration_sent = 1;
        m->mdi_next_announcement = now + 5u * 32768u;
        if (m->mdi_announcements++ < 8)
            fprintf(stderr, "[mdi-peer] sent PhoNet presence announcement for device 7c\n");
    }
    if (tx_write != tx_read) {
        unsigned count = (tx_write + 250u - tx_read) % 250u;
        if (m->mdi_tx_batches++ < 32) {
            fprintf(stderr, "[mdi-peer] consume %u words:", count);
            for (unsigned word = 0; word < count && word < 16; ++word)
                fprintf(stderr, " %04x", memory16(m, 0x05000000 + ((tx_read + word) % 250u) * 2u));
            fputc('\n', stderr);
        }
        m->mdi_tx_words += count;
        for (unsigned word = 0; word < count; ++word) {
            uint16_t value = memory16(m, 0x05000000 + ((tx_read + word) % 250u) * 2u);
            if (m->mdi_tx_length + 2 > sizeof(m->mdi_tx_packet))
                stop_at(m, "mdi_packet_too_large", "mdi", 0x05000000, 0, m->mdi_tx_length);
            m->mdi_tx_packet[m->mdi_tx_length++] = value >> 8;
            m->mdi_tx_packet[m->mdi_tx_length++] = (uint8_t)value;
            if (m->mdi_tx_length >= 6) {
                unsigned expected = 6u + ((unsigned)m->mdi_tx_packet[4] << 8) + m->mdi_tx_packet[5];
                if (m->mdi_tx_length == ((expected + 1u) & ~1u)) {
                    mdi_packet(m, m->mdi_tx_packet, expected);
                    m->mdi_tx_length = 0;
                }
            }
        }
        memory16_set(m, 0x050003EA, tx_write);
        m->irq_pending[2] |= 0x0200;
    }
    if (memory16(m, 0x050003EC) != memory16(m, 0x050003EE)) m->irq_pending[2] |= 0x0400;
    else m->irq_pending[2] &= ~0x0400u;
}


/* Debug helper: RH105_WATCH_RAM=0x349c,0x1238c20 logs every access to the given
   addresses, which makes it cheap to find the code that gates on a RAM word. */
static void ram_watch(const Machine *m, const char *kind, uint32_t address,
                      unsigned width, uint32_t value) {
    (void)width;
    static uint32_t watch[8];
    static unsigned count, init;
    if (!init) {
        init = 1;
        const char *text = getenv("RH105_WATCH_RAM");
        while (text && *text && count < sizeof(watch) / sizeof(watch[0])) {
            watch[count++] = (uint32_t)strtoul(text, (char **)&text, 16);
            if (*text == ',') ++text;
            else break;
        }
    }
    for (unsigned i = 0; i < count; ++i) {
        if (address != watch[i]) continue;
        fprintf(stderr, "[watch] %s %08x value=%08x pc=%08x lr=%08x tick=%" PRIu64 "\n",
                kind, address, value, m->pc, (uint32_t)m->cpu.gprs[ARM_LR],
                m->clock_ticks_q32 >> 32);
        return;
    }
}

static uint32_t read_bus(Machine *m, uint32_t address, unsigned width) {
    if (in_range(address, width, 0x09000000, FLASH_SIZE)) {
        if (flash_special_read(m, address - 0x08000000)) {
            uint32_t physical = address - 0x08000000;
            if (width == 4) return ((uint32_t)flash_word(m, physical) << 16) | flash_word(m, physical + 2);
            uint16_t word = flash_word(m, physical & ~1u);
            return width == 2 ? word : ((address & 1) ? word & 255 : word >> 8);
        }
        if (!m->raw_flash_loaded)
            stop_at(m, "raw_flash_image_missing", "read", address, width, 0);
        uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i) value = (value << 8) | m->memory[address + i];
        return value;
    }
    if (in_range(address, width, FLASH_BASE, FLASH_SIZE) && flash_special_read(m, address)) {
        if (width == 4) return ((uint32_t)flash_word(m, address) << 16) | flash_word(m, address + 2);
        uint16_t word = flash_word(m, address & ~1u);
        return width == 2 ? word : ((address & 1) ? word & 255 : word >> 8);
    }
    if (plain_memory(m, address, width)) {
        uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value = (value << 8) | m->memory[address + i];
        if (m->trace_ram) ram_watch(m, "read ", address, width, value);
        return value;
    }
    uint32_t value;
    unsigned irq_group, irq_kind;
    if (irq_register(address, width, &irq_group, &irq_kind)) {
        value = irq_kind == 0 ? m->irq_pending[irq_group] :
                irq_kind == 1 ? (uint16_t)~m->irq_enabled[irq_group] : m->irq_enabled[irq_group];
        if (irq_kind == 0 && irq_group == 2) value |= 0x6000;
    } else if (address == CTSI_BASE + 0x26 && width == 2) {
        value = 0;
    } else if (address == CTSI_BASE + 0x20A && width == 2) {
        value = gpio_input(m, 0);
    } else if (address == CTSI_BASE + 0x20C && width == 2) {
        value = gpio_input(m, 1);
    } else if (address == CTSI_BASE + 0x230 && width == 2) {
        value = gpio_input(m, 2);
    } else if (address == CTSI_BASE + 0x112 && width == 2) {
        unsigned divider = m->timer2_prescaler & 0x1Fu;
        value = divider - timer2_ticks(m) % (divider + 1u);
    } else if (address == CTSI_BASE + 0x10e && width == 2) {
        value = m->call_timer_divider;
    } else if (address == CTSI_BASE + 0x114 && width == 2) {
        value = m->timer2_prescaler;
    } else if (address == CTSI_BASE + 0x116 && width == 2) {
        value = timer2_value(m);
    } else if (address == UIF_BASE + 0x0C && width == 2) {
        value = (memory16(m, address) & ~0x1Fu) | keypad_columns(m);
    } else if ((address == UIF_BASE + 2 || address == UIF_BASE + 0x0E) && width == 2) {
        value = m->uif_direction[address == UIF_BASE + 2 ? 0 : 1];
    } else if ((address == UIF_BASE + 4 || address == UIF_BASE + 0x10) && width == 2) {
        value = (uint16_t)m->uif_irq_mask[address == UIF_BASE + 4 ? 0 : 1] << 8;
    } else if (address == SIMIF_BASE && width == 2) {
        value = m->sim_status;
    } else if (address == SIMIF_BASE + 6 && width == 2) {
        value = 0;
    } else if (m->virtual_sim_enabled && address == SIMIF_BASE + 0x0c && width == 2) {
        value = m->sim_reply_position < m->sim_reply_length ?
                m->sim_reply[m->sim_reply_position++] : 0xff;
        if (!m->sim_card_ready && m->sim_atr_started && m->sim_reply_position == 2)
            m->sim_card_ready = 1;
    } else if (address == SIMIF_BASE + 0x10 && width == 2) {
        value = m->sim_control;
    } else if (address == UIF_BASE + 0x22 && width == 2) {
        value = 0x0400;
    } else if (address == UIF_BASE + 0x20 && width == 2) {
        value = m->cbus_length;
    } else if (address == UIF_BASE + 0x24 && width == 2) {
        value = m->cbus_high;
    } else if (address == UIF_BASE + 0x26 && width == 2) {
        value = m->cbus_low;
    } else if (address == UIF_BASE + 0x28 && width == 2) {
        value = 0;
        if (m->lcd_command >= 0xDA && m->lcd_command <= 0xDC && m->lcd_read_phase++)
            value = m->lcd_id[m->lcd_command - 0xDA];
    } else if (address == UIF_BASE + 0x2A && width == 2) {
        value = 7;
    } else if (address == UIF_BASE + 0x104 && width == 2) {
        /* FBUS status: transmit FIFO empty and ready; no received bytes. */
        value = 0x0180;
    } else if (address == MCUPLL_BASE && width == 2 && m->pll_written) {
        /* TriX HWemu identifies bit 0 as PLL lock; timing is provisional. */
        value = m->pll_control | ((m->pll_control & 0x10u) ? 1u : 0u);
    } else if (address == DSPPLL_BASE && width == 2 && m->dsp_pll_written) {
        value = m->dsp_pll_control | ((m->dsp_pll_control & 0x10u) ? 1u : 0u);
    } else if (address == CTSI_BASE + 4 && width == 2 && m->ctsi_written) {
        value = m->ctsi_control;
    } else if (address == 0x0600B000 && width == 2) {
        value = 0x2292;
    } else if ((address == 0x0600D00E || address == 0x0600D010) && width == 2) {
        /* Empty STI endpoints during initialization; no host serial peer. */
        value = 0;
    } else if (address == CTSI_BASE && width == 2) {
        /* Powerup reason plus command-complete handshake (bit 9). The value
           reported by TriX HWemu for CTSI+0x0000 is 0x0021. */
        value = m->ctsi_states | 0x0021u;
        if (m->legacy_reset_state &&
            ((m->irq_pending[0] & m->irq_enabled[0]) ||
             (m->irq_pending[1] & m->irq_enabled[1]))) value |= 0x8000;
    } else if (address == CTSI_BASE + 2 && width == 2) {
        /* ASIC identification.  TriX HWemu exposes this as "System Type" at
           CTSI+0x0002 and defaults it to 0x03A6; the firmware reads it at
           0x011efe62 while bringing up the clock tree. */
        value = m->system_type;
    } else if (m->legacy_reset_state && !m->strict_registers &&
               in_range(address, width, CTSI_BASE, 0x200) && width == 2) {
        /* Explicit development compatibility only; unknown hardware reset
           values must not silently become zero in the normal strict model. */
        value = 0;
    } else if (register_memory(address, width)) {
        value = 0;
        for (unsigned i = 0; i < width; ++i) {
            if (!m->register_written[register_index(address + i)] &&
                (!m->legacy_reset_state || m->strict_registers)) {
                if (m->strict_registers)
                    stop_at(m, "unknown_register_reset_value", "read", address, width, 0);
                if (m->unknown_register_traces++ < 64)
                    fprintf(stderr, "[register] unmodelled reset value: address=%08x pc=%08x "
                                    "-> 0\n", address, m->pc);
            }
            value = (value << 8) | m->memory[address + i];
        }
    } else {
        stop_at(m, "unmodeled_memory", "read", address, width, 0);
        return 0;
    }
    if (in_range(address, width, 0x06010800, 0x100) && m->sim_bus_traces++ < 96)
        fprintf(stderr, "[sim-bus] read address=%08x value=%08x pc=%08x\n", address, value, m->pc);
    if (m->trace_uif && width == 2 &&
        (address == UIF_BASE + 0x00 || address == UIF_BASE + 0x02 ||
         address == UIF_BASE + 0x0A || address == UIF_BASE + 0x0E ||
         address == UIF_BASE + 0x0C || address == UIF_BASE + 0x16)) {
        static unsigned uif_reads;
        if (uif_reads++ < 4000)
            fprintf(stderr, "[uif] r%04x pc=%08x lr=%08x value=%08x tick=%" PRIu64 "\n",
                    address - UIF_BASE, m->pc, (uint32_t)m->cpu.gprs[ARM_LR], value,
                    m->clock_ticks_q32 >> 32);
    }
    mmio_log(m, "read", address, width, value);
    return value;
}

static void write_bus(Machine *m, uint32_t address, unsigned width, uint32_t value) {
    if (in_range(address, width, UIF_BASE, 0x1A) && m->lcd_data_bytes >= 15340 &&
        m->graph_control_traces++ < 96)
        fprintf(stderr, "[graph-control] address=%08x value=%08x pc=%08x lr=%08x\n",
                address, value, m->pc, (uint32_t)m->cpu.gprs[ARM_LR]);
    if (in_range(address, width, 0x06010800, 0x100) && m->sim_bus_traces++ < 96)
        fprintf(stderr, "[sim-bus] write address=%08x value=%08x pc=%08x\n", address, value, m->pc);
    if (m->trace_uif && width == 2 &&
        (address == UIF_BASE + 0x00 || address == UIF_BASE + 0x02 ||
         address == UIF_BASE + 0x0A || address == UIF_BASE + 0x0E ||
         address == UIF_BASE + 0x0C || address == UIF_BASE + 0x16)) {
        static unsigned uif_writes;
        if (uif_writes++ < 4000)
            fprintf(stderr, "[uif] w%04x pc=%08x lr=%08x value=%08x tick=%" PRIu64 "\n",
                    address - UIF_BASE, m->pc, (uint32_t)m->cpu.gprs[ARM_LR], value,
                    m->clock_ticks_q32 >> 32);
    }
    if (address >= CTSI_BASE + 0x10A && address <= CTSI_BASE + 0x11A && width == 2 &&
        m->timer_register_writes++ < 32)
        fprintf(stderr, "[timer-register] address=%08x value=%04x pc=%08x\n", address, value, m->pc);
    if (in_range(address, width, 0x09000000, FLASH_SIZE)) {
        flash_write(m, address - 0x08000000, width, value);
        return;
    }
    if (in_range(address, width, FLASH_BASE, FLASH_SIZE)) {
        flash_write(m, address, width, value);
        return;
    }
    if (in_range(address, width, 0, RAM_SIZE) ||
        in_range(address, width, HEADER_RAM_BASE, HEADER_RAM_SIZE) ||
        in_range(address, width, 0x05000000, 0x00100000) ||
        in_range(address, width, 0x07000000, 0x2000)) {
        if (m->trace_scan && address <= 0x3487 && (uint64_t)address + width > 0x3484)
            fprintf(stderr, "[kp-flags] write addr=%08x width=%u value=%08x pc=%08x lr=%08x tick=%" PRIu64 "\n",
                    address, width, value, m->pc, (uint32_t)m->cpu.gprs[ARM_LR],
                    m->clock_ticks_q32 >> 32);
        uint8_t old_mode = m->memory[0x19C4], old_requested = m->memory[0x19C5];
        uint8_t old_error = m->memory[0x19C2];
        uint16_t old_ui_state = (uint16_t)((m->memory[0x43C] << 8) | m->memory[0x43D]);
        uint16_t old_ui_startup = (uint16_t)((m->memory[0x466] << 8) | m->memory[0x467]);
        for (unsigned i = 0; i < width; ++i)
            m->memory[address + i] = (uint8_t)(value >> ((width - i - 1) * 8));
        if (m->trace_ram) ram_watch(m, "write", address, width, value);
        if ((address <= 0x43D && (uint64_t)address + width > 0x43C) ||
            (address <= 0x467 && (uint64_t)address + width > 0x466)) {
            uint16_t state = (uint16_t)((m->memory[0x43C] << 8) | m->memory[0x43D]);
            uint16_t startup = (uint16_t)((m->memory[0x466] << 8) | m->memory[0x467]);
            if ((state != old_ui_state || startup != old_ui_startup) && m->pc != 0x01081C44)
                fprintf(stderr, "[ui-state] state=%04x startup=%04x tick=%" PRIu64 " pc=%08x lr=%08x\n",
                        state, startup, m->clock_ticks_q32 >> 32, m->pc, (uint32_t)m->cpu.gprs[ARM_LR]);
        }
        if (address <= 0x19C5 && (uint64_t)address + width > 0x19C2 &&
            (m->memory[0x19C2] != old_error || m->memory[0x19C4] != old_mode || m->memory[0x19C5] != old_requested))
            fprintf(stderr, "[boot-mode] current=%u requested=%u error=%u pc=%08x lr=%08x r0=%08x r1=%08x r2=%08x r3=%08x\n",
                    m->memory[0x19C4], m->memory[0x19C5], m->memory[0x19C2], m->pc,
                    (uint32_t)m->cpu.gprs[ARM_LR], (uint32_t)m->cpu.gprs[0],
                    (uint32_t)m->cpu.gprs[1], (uint32_t)m->cpu.gprs[2], (uint32_t)m->cpu.gprs[3]);
        return;
    }
    if (in_range(address, width, 0x04000000, 0x01000000)) {
        /* OSMO is a write-only firmware diagnostic transport in TriX HWemu. */
        if (address == 0x04FD0000) {
            if (m->debug_length) {
                m->debug_text[m->debug_length] = 0;
                fprintf(stderr, "[firmware] %s\n", m->debug_text);
                m->debug_length = 0;
            }
        } else {
            for (unsigned i = 0; i < width; ++i) {
                unsigned byte = (value >> ((width - i - 1) * 8)) & 255;
                if (byte >= 32 && byte < 127 && m->debug_length + 1 < sizeof(m->debug_text))
                    m->debug_text[m->debug_length++] = (char)byte;
            }
        }
        return;
    }
    unsigned irq_group, irq_kind;
    if (irq_register(address, width, &irq_group, &irq_kind)) {
        if (irq_kind == 0) m->irq_pending[irq_group] &= ~(uint16_t)value;
        else if (irq_kind == 1) m->irq_enabled[irq_group] &= ~(uint16_t)value;
        else m->irq_enabled[irq_group] |= (uint16_t)value;
        m->cpu.nextEvent = m->cpu.cycles;
    } else if (address == CTSI_BASE + 0x24 && width == 2) {
        if (value & 0x10) m->irq_blocked = 1;
        else if (value & 0x0C) m->irq_blocked = 0;
        /* Do not raise bit 9 here: 0x011edc40 issues this write and then spins
           in `ldrh r0,[r1]; lsls r0,r0,#0x16; bmi` at 0x011edc46, i.e. it waits
           for the command-busy bit to CLEAR (value 0x0021 exits immediately). */
        m->cpu.nextEvent = m->cpu.cycles;
    } else if (address == CTSI_BASE + 0x28 && width == 2) {
        if (value & 0x10) m->fiq_blocked = 1;
        else if (value & 8) m->fiq_blocked = 0;
        m->cpu.nextEvent = m->cpu.cycles;
    } else if (address == SIMIF_BASE && width == 2) {
        m->sim_status &= ~(uint16_t)value;
        if (!m->sim_status) m->irq_pending[0] &= ~4u;
    } else if (address == SIMIF_BASE + 0x12 && width == 2) {
        m->sim_control |= (uint16_t)value;
    } else if (address == SIMIF_BASE + 0x14 && width == 2) {
        m->sim_control &= ~(uint16_t)value;
        if (!(m->sim_control & 1)) {
            m->sim_rx_waiting = m->sim_rx_armed = m->sim_atr_started = 0;
            m->sim_card_ready = 0;
            m->sim_command_length = m->sim_reply_position = m->sim_reply_length = 0;
            m->virtual_sim.directory = m->virtual_sim.selected = 0x3f00;
        }
    } else if (m->virtual_sim_enabled && address == SIMIF_BASE + 0x0c && width == 2) {
        sim_transmit(m, value);
    } else if (address == SIMIF_BASE + 8 && width == 2) {
        memory16_set(m, address, (uint16_t)value);
        /* Model off: the interface accepts the write and nothing follows. */
        if (m->virtual_sim_enabled && (m->sim_control & 1)) {
            clock_sync(m);
            m->sim_rx_deadline = (m->clock_ticks_q32 >> 32) + 32768 / 5;
            m->sim_rx_waiting = 1;
            m->sim_transfer_count = (value & 0x1ff) + 1;
            fprintf(stderr, "[virtual-sim] transfer count=%u pc=%08x\n", m->sim_transfer_count, m->pc);
            m->sim_tx_count = 0;
            m->sim_rx_armed = 1;
            if (!m->sim_atr_started) {
                m->sim_atr_started = 1;
                m->sim_reply[0] = 0x3b;
                m->sim_reply[1] = 0;
                m->sim_reply_length = 2;
                m->sim_reply_position = 0;
                m->sim_reply_ready = (m->clock_ticks_q32 >> 32) + 66;
                fprintf(stderr, "[virtual-sim] ATR 3b 00\n");
            }
        }
    } else if (width == 2 && (address == BRAIN_BASE + 0x10 || address == BRAIN_BASE + 0x20)) {
        unsigned channel = address == BRAIN_BASE + 0x10 ? 0 : 1;
        memory16_set(m, address, (uint16_t)value);
        m->register_written[register_index(address)] = 1;
        m->register_written[register_index(address + 1)] = 1;
        m->dma_lcd_ready[channel] = 0;
        m->dma_lcd_deadline[channel] = 0;
        m->dma_lcd_progress[channel] = 0;
        if (channel == 1) {
            m->dac_position = 0;
            memory16_set(m, BRAIN_BASE + 0x26, 0);
            if (!(value & 1)) m->dac_primed = 0;
        }
    } else if ((address == UIF_BASE + 2 || address == UIF_BASE + 0x0E) && width == 2) {
        /* Low byte sets output pins, high byte clears them.  The scanner at
           0x011f2716 first clears all D1..4 (0x1e00), selects a column (0x0002),
           then releases it (0x0200).  Preserve unrelated pins on either write. */
        unsigned port = address == UIF_BASE + 2 ? 0 : 1;
        m->uif_direction[port] = (uint8_t)((m->uif_direction[port] | value) & ~(value >> 8));
    } else if ((address == UIF_BASE + 4 || address == UIF_BASE + 0x10) && width == 2) {
        /* Latched 16-bit interrupt mask: high byte set, low byte clear. */
        unsigned port = address == UIF_BASE + 4 ? 0 : 1;
        m->uif_irq_mask[port] = (uint8_t)((m->uif_irq_mask[port] & ~(value & 0xFF)) | (value >> 8));
    } else if (width == 2 && (address == CTSI_BASE + 0x202 || address == CTSI_BASE + 0x206 ||
                       address == CTSI_BASE + 0x22C)) {
        unsigned port = address == CTSI_BASE + 0x202 ? 0 : address == CTSI_BASE + 0x206 ? 1 : 2;
        m->gpio_output[port] |= (uint16_t)value;
    } else if (width == 2 && (address == CTSI_BASE + 0x204 || address == CTSI_BASE + 0x208 ||
                              address == CTSI_BASE + 0x22E)) {
        unsigned port = address == CTSI_BASE + 0x204 ? 0 : address == CTSI_BASE + 0x208 ? 1 : 2;
        m->gpio_output[port] &= ~(uint16_t)value;
    } else if (width == 2 && (address == CTSI_BASE + 0x30 || address == CTSI_BASE + 0x32)) {
        memory16_set(m, address, (uint16_t)value);
        if (value & 0x0800) {
            m->call_timer_enabled = address == CTSI_BASE + 0x30;
            if (m->call_timer_enabled) call_timer_arm(m);
            else m->irq_pending[2] &= ~1u;
        }
    } else if (address == CTSI_BASE + 0x10e && width == 2) {
        m->call_timer_divider = value & 0x3fff;
        memory16_set(m, address, (uint16_t)value);
        if (m->call_timer_enabled) call_timer_arm(m);
    } else if (address == CTSI_BASE + 0x114 && width == 2) {
        uint16_t current = timer2_value(m);
        clock_sync(m);
        m->timer2_epoch = m->clock_ticks_q32 >> 32;
        m->timer2_base = current;
        m->timer2_value_epoch = m->clock_ticks_q32 >> 32;
        m->timer2_prescaler = value & 0xFF;
        m->timer2_coarse_slot = 0;
        if (m->timer2_armed) timer2_arm(m);
    } else if (address == CTSI_BASE + 0x116 && width == 2) {
        clock_sync(m);
        m->timer2_base = (uint16_t)value;
        m->timer2_value_epoch = m->clock_ticks_q32 >> 32;
        if (m->timer2_armed) timer2_arm(m);
        fprintf(stderr, "[timer2] counter=%04x pc=%08x\n", value, m->pc);
    } else if (address == CTSI_BASE + 0x118 && width == 2) {
        m->timer2_compare = (uint16_t)value;
        timer2_arm(m);
    } else if (address == UIF_BASE + 0x1A && width == 2) {
        m->lcd_command = (uint8_t)value;
        m->lcd_read_phase = 0;
        if (m->lcd_trace) {
            m->lcd_trace_dirty = 1;
            if (fputc(0, m->lcd_trace) == EOF ||
                fputc(value >> 8, m->lcd_trace) == EOF || fputc(value & 255, m->lcd_trace) == EOF)
                stop_at(m, "lcd_trace_write_failed", "write", address, width, value);
        }
        if (m->lcd_commands++ < 64)
            fprintf(stderr, "[lcd] command=%04x pc=%08x\n", value, m->pc);
    } else if (address == UIF_BASE + 0x1C && width == 2) {
        for (unsigned channel = 0; channel < 2; ++channel) {
            uint32_t control = BRAIN_BASE + 0x10 + channel * 0x10;
            if ((memory16(m, control) & 1) && memory32(m, control + 8) == address)
                m->dma_lcd_ready[channel] = 1;
        }
        if (m->lcd_data_bytes >= 15340 && m->lcd_data_bytes < 15356)
            fprintf(stderr, "[graph-data] value=%04x command=%02x pc=%08x lr=%08x\n",
                    value, m->lcd_command, m->pc, (uint32_t)m->cpu.gprs[ARM_LR]);
        if (m->lcd_trace) {
            m->lcd_trace_dirty = 1;
            if (fputc(1, m->lcd_trace) == EOF ||
                fputc(value >> 8, m->lcd_trace) == EOF || fputc(value & 255, m->lcd_trace) == EOF)
                stop_at(m, "lcd_trace_write_failed", "write", address, width, value);
        }
        if (m->lcd_data_bytes++ < 64)
            fprintf(stderr, "[lcd] data=%04x pc=%08x\n", value, m->pc);
    } else if (address == UIF_BASE + 0x38 && width == 2) {
        m->dac_value = (int16_t)value;
        m->dac_previous = m->dac_value;
        if (memory16(m, UIF_BASE + 0x3c) & 1) m->dac_primed = 1;
    } else if (address == UIF_BASE + 0x3c && width == 2) {
        memory16_set(m, address, (uint16_t)value);
        if (!(value & 1)) {
            m->dac_primed = 0;
            m->dac_value = 0;
            m->dac_previous = 0;
            m->dac_resample = 0;
        }
    } else if (address == UIF_BASE + 0x20 && width == 2) {
        m->cbus_length = (uint16_t)value;
    } else if (address == UIF_BASE + 0x22 && width == 2) {
        m->cbus_command = (uint16_t)value;
        if (value & 0x0100) {
            uint32_t reply = cbus_read(m, (value >> 5) & 7, value & 31);
            m->cbus_high = reply >> 16;
            m->cbus_low = reply & 0xFFFF;
        }
    } else if (address == UIF_BASE + 0x24 && width == 2) {
        m->cbus_high = (uint16_t)value;
    } else if (address == UIF_BASE + 0x26 && width == 2) {
        m->cbus_low = (uint16_t)value;
        if (m->cbus_command & 0x0200)
            cbus_write(m, (m->cbus_command >> 5) & 7, m->cbus_command & 31,
                       ((uint32_t)m->cbus_high << 16) | m->cbus_low);
    } else if (address == MCUPLL_BASE && width == 2) {
        clock_sync(m);
        m->pll_control = (uint16_t)value;
        m->pll_written = 1;
        unsigned multiplier = (value >> 7) & 31;
        unsigned divider = 1u << ((value >> 5) & 3);
        uint64_t hz = multiplier && (value & 0x10) ? 13000000ull * multiplier / divider : 13000000ull;
        m->clock_step_q32 = (32768ull << 32) / hz;
    } else if (address == DSPPLL_BASE && width == 2) {
        m->dsp_pll_control = (uint16_t)value;
        m->dsp_pll_written = 1;
    } else if (address == CTSI_BASE + 4 && width == 2) {
        m->ctsi_control = (uint16_t)value;
        m->ctsi_written = 1;
    } else if (address == CTSI_BASE + 2 && width == 2) {
        m->system_type |= value & 0x78;
    } else if (register_memory(address, width)) {
        /* Storage-only prototype: peripheral side effects are still missing. */
        for (unsigned i = 0; i < width; ++i) {
            m->memory[address + i] = (uint8_t)(value >> ((width - i - 1) * 8));
            m->register_written[register_index(address + i)] = 1;
        }
    } else {
        stop_at(m, "unmodeled_memory", "write", address, width, value);
    }
    mmio_log(m, "write", address, width, value);
}

static void dma_poll(Machine *m) {
    for (unsigned channel = 0; channel < 2; ++channel) {
        uint32_t registers = BRAIN_BASE + 0x10 + channel * 0x10;
        uint16_t control = memory16(m, registers);
        if (!(control & 1)) {
            m->dma_lcd_ready[channel] = 0;
            m->dma_lcd_deadline[channel] = 0;
            m->dma_lcd_progress[channel] = 0;
            continue;
        }
        if (!m->dma_lcd_ready[channel]) continue;
        uint32_t peripheral = memory32(m, registers + 8);
        if (peripheral != UIF_BASE + 0x1C || (control & 0x0C) != 8) continue;
        if ((control & 0xC0) != 0x40)
            stop_at(m, "unsupported_lcd_dma_width", "dma", peripheral, 2, control);
        uint32_t source = memory32(m, registers + 12);
        unsigned count = memory16(m, registers + 4);
        uint64_t now = m->clock_ticks_q32 >> 32;
        if (!m->dma_lcd_deadline[channel]) {
            /* Serial LCD transfers cannot finish at the FIFO-priming write.
               In particular, 011ee7d4 starts DMA before 011ee7e8 publishes
               the completion token: synchronous completion leaks the LCD
               semaphore and later deadlocks the keypad task. Use a deferred
               nine-bit serial transfer. The provisional 2.5 MHz board clock
               is adjustable with RH105_LCD_HZ; the old 1 Mbit/s placeholder
               imposed over 100 ms of extra wait on every full redraw. */
            uint64_t ticks = ((uint64_t)count * 9 * 32768 + m->lcd_serial_hz - 1) /
                             m->lcd_serial_hz;
            m->dma_lcd_deadline[channel] = now + (ticks ? ticks : 1);
            m->dma_lcd_start[channel] = now;
            m->dma_lcd_next_chunk[channel] = now + 33;
            m->dma_lcd_progress[channel] = 0;
            if (m->trace_lcd_timing)
                fprintf(stderr, "[timing] lcd-start channel=%u bytes=%u tick=%" PRIu64
                        " deadline=%" PRIu64 " wall_ns=%" PRIu64 "\n",
                        channel, count, now, m->dma_lcd_deadline[channel], monotonic_ns());
            continue;
        }
        int complete = now >= m->dma_lcd_deadline[channel];
        if (!complete && now < m->dma_lcd_next_chunk[channel]) continue;
        uint64_t transferred = (now - m->dma_lcd_start[channel]) * m->lcd_serial_hz /
                               (9u * 32768u);
        unsigned end = complete || transferred > count ? count : (unsigned)transferred;
        unsigned first = m->dma_lcd_progress[channel];
        if (control & 0x200) source += first;
        /* The LCD writer primes its FIFO with byte zero after arming DMA.
           Publish the bytes already clocked onto the panel in small batches;
           the completion IRQ still waits for the final serial byte. */
        for (unsigned i = first; i < end; ++i) {
            uint32_t value = read_bus(m, source, 1);
            write_bus(m, peripheral, 2, value);
            if (control & 0x200) ++source;
        }
        m->dma_lcd_bytes += end - first;
        m->dma_lcd_progress[channel] = end;
        m->dma_lcd_next_chunk[channel] = now + 131; /* About 4 ms. */
        if (m->lcd_trace && fflush(m->lcd_trace))
            stop_at(m, "lcd_trace_write_failed", "dma", peripheral, 0, 0);
        if (m->trace_lcd_timing && !first && end)
            fprintf(stderr, "[timing] lcd-first channel=%u bytes=%u tick=%" PRIu64
                    " wall_ns=%" PRIu64 "\n", channel, end, now, monotonic_ns());
        if (!complete) continue;
        if (m->dma_completions[channel] < 12)
            fprintf(stderr, "[dma] channel=%u source=%08x destination=%08x bytes=%u control=%04x\n",
                    channel, memory32(m, registers + 12), peripheral, count, control);
        ++m->dma_completions[channel];
        if (m->trace_lcd_timing)
            fprintf(stderr, "[timing] lcd-done channel=%u tick=%" PRIu64 " wall_ns=%" PRIu64 "\n",
                    channel, now, monotonic_ns());
        m->dma_lcd_ready[channel] = 0;
        m->dma_lcd_deadline[channel] = 0;
        m->dma_lcd_progress[channel] = 0;
        memory16_set(m, registers + 4, 0);
        memory16_set(m, registers, (control & ~1u) | 2u);
        if (channel == 0) m->irq_pending[2] |= 0x0040;
        else m->irq_pending[0] |= 0x0800;
    }
}

static uint32_t load32(struct ARMCore *cpu, uint32_t address, int *cycles) {
    /* LDR: one data bus cycle and one internal cycle beyond the fetch. */
    if (cycles) *cycles += 2;
    Machine *m = owner(cpu);
    uint32_t aligned = address & ~3u;
    uint32_t value;
    if (!m->trace_ram && (aligned < RAM_SIZE ||
        (!m->flash_mode && in_range(aligned, 4, FLASH_BASE, FLASH_SIZE)))) {
        LOAD_32BE(value, aligned, m->memory);
    } else value = read_bus(m, aligned, 4);
    unsigned shift = (address & 3) * 8;
    return shift ? (value >> shift) | (value << (32 - shift)) : value;
}

static uint32_t load16(struct ARMCore *cpu, uint32_t address, int *cycles) {
    if (cycles) *cycles += 2;
    if (address & 1)
        stop_at(owner(cpu), "unsupported_unaligned_halfword", "read", address, 2, 0);
    Machine *m = owner(cpu);
    if (!m->trace_ram && (address < RAM_SIZE ||
        (!m->flash_mode && in_range(address, 2, FLASH_BASE, FLASH_SIZE)))) {
        uint16_t value;
        LOAD_16BE(value, address, m->memory);
        return value;
    }
    return read_bus(m, address, 2);
}

static uint32_t load8(struct ARMCore *cpu, uint32_t address, int *cycles) {
    if (cycles) *cycles += 2;
    Machine *m = owner(cpu);
    if (!m->trace_ram && (address < RAM_SIZE ||
        (!m->flash_mode && in_range(address, 1, FLASH_BASE, FLASH_SIZE))))
        return m->memory[address];
    return read_bus(m, address, 1);
}

/* Stack/data writes bypass device dispatch. Keep the boot/UI watches and all
   requested memory/scan tracing on the ordinary bus path. */
static int direct_ram_write(const Machine *m, uint32_t address, unsigned width) {
    return address >= 0x19c6 && address <= RAM_SIZE - width &&
           !m->trace_ram && !m->trace_scan;
}

static void store32(struct ARMCore *cpu, uint32_t address, int32_t value, int *cycles) {
    if (cycles) ++*cycles;
    Machine *m = owner(cpu);
    address &= ~3u;
    if (direct_ram_write(m, address, 4)) {
        STORE_32BE((uint32_t)value, address, m->memory);
    } else write_bus(m, address, 4, (uint32_t)value);
}

static void store16(struct ARMCore *cpu, uint32_t address, int16_t value, int *cycles) {
    if (cycles) ++*cycles;
    if (address & 1)
        stop_at(owner(cpu), "unsupported_unaligned_halfword", "write", address, 2, (uint16_t)value);
    Machine *m = owner(cpu);
    if (direct_ram_write(m, address, 2)) {
        STORE_16BE((uint16_t)value, address, m->memory);
    } else write_bus(m, address, 2, (uint16_t)value);
}

static void store8(struct ARMCore *cpu, uint32_t address, int8_t value, int *cycles) {
    if (cycles) ++*cycles;
    Machine *m = owner(cpu);
    if (direct_ram_write(m, address, 1)) m->memory[address] = (uint8_t)value;
    else write_bus(m, address, 1, (uint8_t)value);
}

static uint32_t multiple(struct ARMCore *cpu, uint32_t base, int mask,
                         enum LSMDirection direction, int *cycles, int write) {
    /* ARM7TDMI gives empty lists special PC/0x40-writeback semantics.
       Until modeled, stop explicitly rather than silently doing no transfers. */
    if (!(mask & 0xffff))
        stop_at(owner(cpu), "unsupported_empty_register_list", write ? "write" : "read", base, 4, 0);
    unsigned count = (unsigned)__builtin_popcount((unsigned)mask & 0xFFFFu);
    uint32_t address = base;
    if (direction == LSM_IB) address += 4;
    if (direction == LSM_DA) address -= count * 4 - 4;
    if (direction == LSM_DB) address -= count * 4;
    address &= ~3u;
    /* STM: n data cycles. LDM: n data cycles plus ONE internal cycle,
       not an internal cycle per register. The core charges fetch/refill. */
    if (cycles) *cycles += count + (write ? 0 : 1);
    Machine *m = owner(cpu);
    int direct = write ? direct_ram_write(m, address, count * 4) :
        (!m->trace_ram && (in_range(address, count * 4, 0, RAM_SIZE) ||
         (!m->flash_mode && in_range(address, count * 4, FLASH_BASE, FLASH_SIZE))));
    for (unsigned registers = (unsigned)mask & 0xffff; registers; registers &= registers - 1) {
        unsigned i = (unsigned)__builtin_ctz(registers);
        if (direct) {
            if (write) { STORE_32BE((uint32_t)cpu->gprs[i], address, m->memory); }
            else { uint32_t value; LOAD_32BE(value, address, m->memory); cpu->gprs[i] = (int32_t)value; }
        } else if (write) store32(cpu, address, cpu->gprs[i], NULL);
        else cpu->gprs[i] = (int32_t)load32(cpu, address, NULL);
        address += 4;
    }
    return direction & LSM_D ? base - count * 4 : base + count * 4;
}

static uint32_t load_multiple(struct ARMCore *cpu, uint32_t base, int mask,
                              enum LSMDirection direction, int *cycles) {
    return multiple(cpu, base, mask, direction, cycles, 0);
}

static uint32_t store_multiple(struct ARMCore *cpu, uint32_t base, int mask,
                               enum LSMDirection direction, int *cycles) {
    return multiple(cpu, base, mask, direction, cycles, 1);
}

static void active_region(struct ARMCore *cpu, uint32_t address) {
    Machine *m = owner(cpu);
    unsigned width = cpu->cpsr.t ? 4 : 8;
    if (m->fetch_size >= width && address - m->fetch_base <= m->fetch_size - width)
        return;
    static const RegisterRange regions[] = {
        {0, RAM_SIZE}, {FLASH_BASE, FLASH_SIZE}, {HEADER_RAM_BASE, HEADER_RAM_SIZE},
        {0x05000000, 0x00100000}, {0x07000000, 0x2000},
    };
    for (unsigned i = 0; i < sizeof(regions) / sizeof(regions[0]); ++i) {
        if (in_range(address, width, regions[i].base, regions[i].size)) {
            m->fetch_base = regions[i].base;
            m->fetch_size = regions[i].size;
            return;
        }
    }
    if (m->rom_size && in_range(address, width, 0x00800000, m->rom_size)) {
        m->fetch_base = 0x00800000;
        m->fetch_size = m->rom_size;
    } else if (m->rom_hle && in_range(address, width, 0x00840000, 0x48)) {
        m->fetch_base = 0x00840000;
        m->fetch_size = 0x48;
    } else stop_at(m, "unmodeled_instruction_memory", "fetch", address, 0, 0);
}

/* Fold only complete, taken iterations of the firmware's calibrated Thumb
   countdown. This is NOT a sleep/idle-task shortcut: memory, I/O and scheduler
   loops remain interpreted. Stop strictly before the next core event, leave the
   terminal SUBS/BNE interpreted, and preserve registers, flags and history. */
static int countdown_fastforward(Machine *m, uint64_t limit) {
    struct ARMCore *cpu = &m->cpu;
    if (!cpu->cpsr.t || cpu->prefetch[0] != 0x3801 || cpu->prefetch[1] != 0xd1fd ||
        memory16(m, m->pc) != 0x3801 || memory16(m, m->pc + 2) != 0xd1fd ||
        cpu->memory.activeSeqCycles16 || cpu->memory.activeNonseqCycles16)
        return 0;
    uint32_t value = (uint32_t)cpu->gprs[0];
    int64_t budget = (int64_t)cpu->nextEvent - cpu->cycles - 1;
    if (value < 2 || budget < 4 || limit - m->steps < 2) return 0;
    uint64_t iterations = (uint64_t)budget / 4;
    if (iterations > value - 1) iterations = value - 1;
    if (iterations > (limit - m->steps) / 2) iterations = (limit - m->steps) / 2;
    uint32_t result = value - iterations;
    cpu->gprs[0] = (int32_t)result;
    cpu->cpsr.n = result >> 31;
    cpu->cpsr.z = 0; /* We deliberately never fold the terminal iteration. */
    cpu->cpsr.c = 1;
    cpu->cpsr.v = result == 0x7fffffff; /* Overflow of the LAST subtraction. */
    cpu->cycles += (int32_t)(iterations * 4); /* SUBS=1, taken BNE=3. */
    uint64_t instructions = iterations * 2;
    uint64_t first = instructions > HISTORY ? instructions - HISTORY : 0;
    for (uint64_t i = first; !m->no_history && i < instructions; ++i) {
        unsigned slot = (m->steps + i) % HISTORY;
        m->history[slot] = m->pc + (i & 1) * 2;
        m->states[slot] = 1;
        m->opcodes[slot] = i & 1 ? 0xd1fd : 0x3801;
    }
    m->steps += instructions;
    m->pc += 2; /* The last executed instruction, as in the reference loop. */
    return 1;
}

static int32_t stall(struct ARMCore *cpu, int32_t cycles) { (void)cpu; return cycles; }
static void reset(struct ARMCore *cpu) { (void)cpu; }
static void read_cpsr(struct ARMCore *cpu) { (void)cpu; }
/* ---- UEM buzzer output -------------------------------------------------
 * The firmware drives its alert tone/keypad beep transducer through CBUS
 * device 1 register 0x18 (module `hw_buzz.c`, driver 0x01145104).  The exact
 * divider->frequency law is not recoverable from the image: it runs through
 * two runtime clock helpers (0x011efe9a, 0x011f690c = __aeabi_uidiv) whose
 * inputs are board constants, so the buzzer base clock is exposed as
 * RH105_BUZZER_CLK (Hz, default 2 MHz) with
 *
 *     f = clk / (2 * (divider + 1))
 *
 * which puts the dividers the driver produces in the audible 0.5-4 kHz band.
 * Samples are streamed to a 16-bit mono 44.1 kHz WAV named by RH105_WAV.
 */
static FILE *audio_stream;

/* Set when the audio sink is headerless s16le (RH105_PCM, or a WAV stream on
   stdout): there is no RIFF header to patch and the sink may not be seekable. */
static int audio_raw;

static void audio_finalize(void) {
    if (!audio_stream) return;
    uint32_t frames = 0;
    if (fseek(audio_stream, 0, SEEK_END) == 0) {
        long size = ftell(audio_stream);
        if (size > 44) frames = (uint32_t)((size - 44) / 2);
    }
    uint8_t header[44] = {0};
    uint32_t data_bytes = frames * 2, byte_rate = AUDIO_RATE * 2;
    memcpy(header, "RIFF", 4);
    header[4] = (uint8_t)((36 + data_bytes) >> 0);
    header[5] = (uint8_t)((36 + data_bytes) >> 8);
    header[6] = (uint8_t)((36 + data_bytes) >> 16);
    header[7] = (uint8_t)((36 + data_bytes) >> 24);
    memcpy(header + 8, "WAVEfmt ", 8);
    header[16] = 16; header[20] = 1; header[22] = 1;
    header[24] = (uint8_t)AUDIO_RATE; header[25] = (uint8_t)(AUDIO_RATE >> 8);
    header[28] = (uint8_t)byte_rate; header[29] = (uint8_t)(byte_rate >> 8);
    header[30] = (uint8_t)(byte_rate >> 16); header[31] = (uint8_t)(byte_rate >> 24);
    header[32] = 2; header[34] = 16;
    memcpy(header + 36, "data", 4);
    header[40] = (uint8_t)data_bytes; header[41] = (uint8_t)(data_bytes >> 8);
    header[42] = (uint8_t)(data_bytes >> 16); header[43] = (uint8_t)(data_bytes >> 24);
    if (fseek(audio_stream, 0, SEEK_SET) == 0) fwrite(header, 1, sizeof(header), audio_stream);
    fclose(audio_stream);
    audio_stream = NULL;
}

static void audio_flush(Machine *m) {
    if (!m->audio_out || !m->audio_pending) return;
    if (fwrite(m->audio_buffer, 1, m->audio_pending, m->audio_out) != m->audio_pending ||
        fflush(m->audio_out)) {
        if (audio_raw && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            clearerr(m->audio_out);
        } else {
            fprintf(stderr, "[audio] output disabled: %s\n", strerror(errno));
            m->audio_out = NULL;
        }
    }
    m->audio_pending = 0;
}

static int16_t dac_output(Machine *m) {
    /* DMA1 continuously walks the two 40 kHz PCM halves. The first sample
       primes UIF+0x38; the transfer counter and FIQ drive firmware refills. */
    uint16_t control = memory16(m, BRAIN_BASE + 0x20);
    if (!m->dac_primed || !(control & 1) || !(memory16(m, UIF_BASE + 0x3c) & 1) ||
        memory32(m, BRAIN_BASE + 0x28) != UIF_BASE + 0x38)
        return 0;
    m->dac_resample += DAC_RATE;
    if (m->dac_resample >= AUDIO_RATE) {
        m->dac_resample -= AUDIO_RATE;
        uint32_t count = memory16(m, BRAIN_BASE + 0x24);
        if (++m->dac_position > count) {
            m->dac_position = 0;
            ++m->dma_completions[1];
            m->irq_pending[0] |= 0x0800;
        }
        uint32_t address = memory32(m, BRAIN_BASE + 0x2c) + m->dac_position * 2;
        if (!in_range(address, 2, 0, RAM_SIZE))
            stop_at(m, "unsupported_audio_dma_source", "dma", address, 2, control);
        m->dac_previous = m->dac_value;
        m->dac_value = (int16_t)memory16(m, address);
        memory16_set(m, BRAIN_BASE + 0x26, m->dac_position);
        ++m->dac_samples;
        if (m->dac_value) ++m->dac_nonzero_samples;
    }
    return (int16_t)(m->dac_previous +
                    (int64_t)(m->dac_value - m->dac_previous) * m->dac_resample / AUDIO_RATE);
}

static void audio_poll(Machine *m) {
    uint64_t now = m->clock_ticks_q32 >> 32;
    if (!m->audio_started) {
        m->audio_started = 1;
        m->audio_last_tick = now;
        const char *path = getenv("RH105_WAV");
        /* RH105_PCM=<path|-> selects a headerless s16le stream at AUDIO_RATE.
           Because nothing is ever sought, the sink may be a FIFO, which is
           how the Tk GUI feeds `aplay`/`pacat` a live signal.  RH105_WAV
           keeps the seekable RIFF behaviour with the header patched at exit. */
        const char *raw_path = getenv("RH105_PCM");
        int want_raw = raw_path && *raw_path;
        if (want_raw) path = raw_path;
        if (path && *path) {
            if (strcmp(path, "-") == 0) {
                audio_stream = stdout;
                want_raw = 1;
                int flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
                if (flags >= 0) fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
                setvbuf(stdout, NULL, _IONBF, 0);
            } else {
                if (want_raw) {
                    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, 0666);
                    audio_stream = fd < 0 ? NULL : fdopen(fd, "wb");
                    if (fd >= 0 && !audio_stream) close(fd);
                    if (audio_stream) setvbuf(audio_stream, NULL, _IONBF, 0);
                } else audio_stream = fopen(path, "wb");
                if (!audio_stream) fprintf(stderr, "[audio] cannot open %s: %s\n", path, strerror(errno));
                if (audio_stream && !want_raw) {
                    uint8_t blank[44] = {0};
                    fwrite(blank, 1, sizeof(blank), audio_stream);
                }
            }
            if (audio_stream) {
                audio_raw = want_raw;
                m->audio_out = audio_stream;
                if (audio_stream != stdout && !audio_raw) atexit(audio_finalize);
            }
        }
        /* Hardware self-test: drive the emulated UEM buzzer exactly as the
           firmware's `hw_buzz.c` driver does, so the audio chain (divider ->
           square wave -> WAV) can be validated without needing the UI to
           actually request a tone.  RH105_BUZZER_TEST=<divider>.  It is
           re-applied every poll because the firmware programs reg 0x18 to
           "off" several times while it boots. */
        const char *test = getenv("RH105_BUZZER_TEST");
        if (test && *test) {
            m->buzzer_test = (uint16_t)(strtoul(test, NULL, 0) & BUZZER_DIVIDER);
            m->buzzer_test_divider = 1;
            fprintf(stderr, "[buzzer] self-test divider=%u (~%.0f Hz)\n", m->buzzer_test,
                    2000000.0 / (2.0 * (double)(m->buzzer_test + 1u)));
        }
    }
    if (now <= m->audio_last_tick) {
        m->audio_last_tick = now;
        return;
    }
    if (m->buzzer_test_divider) {
        m->buzzer_enable = 1;
        m->buzzer_divider = m->buzzer_test;
    }
    /* Convert the elapsed 32.768 kHz tick delta into host sample frames. */
    uint64_t ticks = now - m->audio_last_tick;
    m->audio_last_tick = now;
    m->audio_frac += ticks * AUDIO_RATE;
    uint64_t frames = m->audio_frac / 32768;
    m->audio_frac %= 32768;
    if (!frames) return;
    /* The DAC clock and refill interrupts continue without a host player. */
    if (!m->audio_out) {
        if (m->dac_primed)
            for (uint64_t i = 0; i < frames; ++i) dac_output(m);
        return;
    }

    static double amp;
    static int amp_init;
    if (!amp_init) {
        amp_init = 1;
        amp = 9000.0;
        const char *env = getenv("RH105_BUZZER_AMP");
        if (env) amp = strtod(env, NULL);
        if (!isfinite(amp)) amp = 9000.0;
        if (amp < 0.0) amp = 0.0;
        if (amp > 32767.0) amp = 32767.0;
    }
    double step = 0.0;
    if (m->buzzer_enable) {
        static double clk;
        static int clk_init;
        if (!clk_init) {
            clk_init = 1;
            clk = 2000000.0;
            const char *env = getenv("RH105_BUZZER_CLK");
            if (env) clk = strtod(env, NULL);
            if (!isfinite(clk) || clk <= 0.0) clk = 2000000.0;
        }
        double freq = clk / (2.0 * (double)(m->buzzer_divider + 1u));
        if (freq > AUDIO_RATE / 2.0) freq = AUDIO_RATE / 2.0;
        step = 2.0 * freq / (double)AUDIO_RATE;
    }

    uint64_t written = 0;
    while (written < frames) {
        size_t chunk = (size_t)(frames - written);
        size_t available = (sizeof(m->audio_buffer) - m->audio_pending) / 2;
        if (chunk > available) chunk = available;
        uint8_t *block = m->audio_buffer + m->audio_pending;
        for (size_t i = 0; i < chunk; ++i) {
            int32_t sample = dac_output(m);
            if (step > 0.0) {
                m->audio_phase += step;
                if (m->audio_phase >= 2.0) m->audio_phase -= 2.0;
                sample += (m->audio_phase < 1.0) ? (int16_t)amp : (int16_t)-amp;
            }
            if (sample > INT16_MAX) sample = INT16_MAX;
            if (sample < INT16_MIN) sample = INT16_MIN;
            block[2 * i] = (uint16_t)sample & 255;
            block[2 * i + 1] = (uint16_t)sample >> 8;
        }
        m->audio_pending += chunk * 2;
        if (m->audio_pending == sizeof(m->audio_buffer)) {
            audio_flush(m);
            if (!m->audio_out) return;
        }
        written += chunk;
        m->audio_samples += (uint32_t)chunk;
    }
    /* 512 frames add at most 11.6 ms of output latency. Writing every sample
       separately woke the GUI and audio player tens of thousands of times/s. */
}

static void events(struct ARMCore *cpu) {
    Machine *m = owner(cpu);
    int advanced;
    if (stop_requested) stop_at(m, "user_exit", "signal", m->pc, 0, 0);
    clock_sync(m);
    advanced = (m->clock_ticks_q32 >> 32) != m->events_tick;
    if (advanced) m->events_tick = m->clock_ticks_q32 >> 32;
    cpu->cycles = 0;
    m->clock_last_cycles = 0;
    if (m->realtime) realtime_pace(m);
    /* Bus accesses and key edges force events() so the guest sees hardware
       state immediately, which can happen many times inside one 32768 Hz
       tick. Everything below only changes when the emulated clock counts,
       so it runs once per tick instead of once per bus cycle. State that can
       change without the clock (IRQ bits, FIFO contents) stays ungated. */
    if (advanced) keypad_poll(m);
    /* The LCD trace is buffered for throughput, so flush it here: this runs
       often enough that a GUI sees each panel update within milliseconds,
       and the dirty flag keeps the common case to one predictable branch. */
    if (m->lcd_trace_dirty && m->lcd_trace) {
        m->lcd_trace_dirty = 0;
        if (fflush(m->lcd_trace)) stop_at(m, "lcd_trace_write_failed", "flush", 0, 0, 0);
    }
    if (m->trace_pc) {
        static unsigned seen[65536];
        uint32_t pc = m->pc;
        if (pc >= 0x011f2700 && pc < 0x011f27d0 && !seen[pc & 0xFFFF]++)
            fprintf(stderr, "[pc-trace] entered %08x tick=%" PRIu64 "\n", pc, m->clock_ticks_q32 >> 32);
    }
    if (advanced) {
        dma_poll(m);
        audio_poll(m);
        mdi_poll(m);
        sim_poll(m);
        if (m->nvram.path && m->nvram_dirty &&
            (m->clock_ticks_q32 >> 32) >= m->nvram_next_save) {
            m->nvram_next_save = (m->clock_ticks_q32 >> 32) + 2 * 32768;
            if (nvram_save(&m->nvram, m->memory + NVRAM_BASE)) m->nvram_dirty = 0;
        }
        if (m->virtual_sim_enabled && m->sim_rx_waiting &&
            (m->clock_ticks_q32 >> 32) >= m->sim_rx_deadline) {
            /* Firmware's SIM FIQ handler treats status bit 0 as receive failure.
               No ATR arrives from the empty slot; 200 ms is provisional timing. */
            m->sim_rx_waiting = 0;
            m->sim_status |= 1;
            ++m->sim_rx_timeouts;
            fprintf(stderr, "[sim-if] receive timeout\n");
        }
    }
    if (m->virtual_sim_enabled && m->sim_status) m->irq_pending[0] |= 4;
    /* UEM is CTSI source 0x400 (group 2 bit 15), registered by 011f2272.
       SIMIF itself uses FIQ source 9, group 0 bit 2. */
    if (m->cbus_registers[1][0x15] & ~m->cbus_registers[1][0x16])
        m->irq_pending[2] |= 0x8000;
    else m->irq_pending[2] &= ~0x8000u;
    if (advanced) {
        if (m->call_timer_enabled && m->clock_ticks_q32 >= m->call_timer_deadline_q32) {
            uint64_t elapsed = 1 + (m->clock_ticks_q32 - m->call_timer_deadline_q32) /
                                  m->call_timer_period_q32;
            m->call_timer_deadline_q32 += elapsed * m->call_timer_period_q32;
            m->call_timer_ticks += elapsed;
            m->irq_pending[2] |= 1;
        }
        if (m->timer2_prescaler & 0x80) {
            /* The secondary OS timer list uses units of eight Timer2 counts. */
            uint64_t slot = ((m->clock_ticks_q32 >> 32) - m->timer2_value_epoch) /
                            (((m->timer2_prescaler & 0x1Fu) + 1u) * 8u);
            if (slot != m->timer2_coarse_slot) {
                m->timer2_coarse_slot = slot;
                m->irq_pending[2] |= 0x0100;
                ++m->timer2_coarse_events;
            }
        }
        if (m->timer2_armed && (m->clock_ticks_q32 >> 32) >= m->timer2_deadline) {
            /* Firmware registers the compare service as CTSI source 0x408. */
            m->irq_pending[2] |= 0x0080;
            m->timer2_armed = 0;
            ++m->timer2_matches;
        }
    }
    if (!m->fiq_blocked && !cpu->cpsr.f &&
        ((m->irq_pending[0] & m->irq_enabled[0]) || (m->irq_pending[1] & m->irq_enabled[1]))) {
        ++m->fiq_deliveries;
        ARMRaiseFIQ(cpu);
    } else if (!m->irq_blocked && !cpu->cpsr.i) {
        for (unsigned group = 2; group < 7; ++group) {
            unsigned pending = m->irq_pending[group] | (group == 2 ? 0x6000 : 0);
            if (pending & m->irq_enabled[group]) {
                ++m->irq_deliveries;
                ARMRaiseIRQ(cpu);
                break;
            }
        }
    }
    if (m->trace_progress) {
        uint64_t tick = m->clock_ticks_q32 >> 32;
        if (tick >= m->progress_next) {
            m->progress_next = tick + 32768;
            unsigned slot = m->steps ? (unsigned)((m->steps - 1) % HISTORY) : 0;
            fprintf(stderr, "[progress] t=%" PRIu64 " steps=%" PRIu64 " pc=%08x last=%08x "
                            "lcd=%u/%u dma=%llu sim=%u irq=%u/%u t2=%u\n",
                    tick, m->steps, m->pc, m->no_history ? m->pc : m->history[slot],
                    m->lcd_commands, m->lcd_data_bytes,
                    (unsigned long long)m->dma_lcd_bytes, m->virtual_sim.commands, m->irq_deliveries, m->fiq_deliveries,
                    m->timer2_matches);
        }
    }
    for (unsigned i = 0; i < m->poke_count; ++i) {
        uint16_t value = (uint16_t)m->pokes[i].value;
        m->memory[m->pokes[i].address & (RAM_SIZE - 1)] = (uint8_t)(value >> 8);
        m->memory[(m->pokes[i].address + 1) & (RAM_SIZE - 1)] = (uint8_t)value;
    }
    cpu->nextEvent = cpu->cycles + 4096;
}

static int writable_ram(uint32_t address, unsigned width) {
    return in_range(address, width, 0, RAM_SIZE) ||
           in_range(address, width, HEADER_RAM_BASE, HEADER_RAM_SIZE) ||
           in_range(address, width, 0x05000000, 0x00100000) ||
           in_range(address, width, 0x07000000, 0x2000);
}

static void rom_return(struct ARMCore *cpu) {
    uint32_t link = cpu->gprs[ARM_LR];
    _ARMSetMode(cpu, link & 1u ? MODE_THUMB : MODE_ARM);
    cpu->gprs[ARM_PC] = link & ~1u;
    cpu->cycles += cpu->cpsr.t ? ThumbWritePC(cpu) : ARMWritePC(cpu);
}

static void rom_safer(Machine *m, int decode) {
    struct ARMCore *cpu = &m->cpu;
    uint32_t data = cpu->gprs[0], length = cpu->gprs[1], workspace = cpu->gprs[2];
    uint8_t mode = cpu->gprs[3];
    /* The H8 routines process a full final block even for a partial length. */
    if (length > RAM_SIZE)
        stop_at(m, "invalid_rom_cipher_length", "cipher", data, 0, length);
    uint32_t extent = (length + 7u) & ~7u;
    if (!writable_ram(data, extent) || !writable_ram(workspace, TDS6_SAFER_WORKSPACE))
        stop_at(m, "invalid_rom_cipher_buffer", "cipher", data, 0, length);
    if ((uint64_t)data < (uint64_t)workspace + TDS6_SAFER_WORKSPACE &&
        (uint64_t)workspace < (uint64_t)data + extent)
        stop_at(m, "unsupported_overlapping_rom_cipher_buffers", "cipher", data, 0, length);
    fprintf(stderr, "[tds6-safer] %s data=%08x length=%u workspace=%08x mode=%02x; ASIC compatibility unverified\n",
            decode ? "decode" : "encode", data, length, workspace, mode);
    tds6_safer_cbc(m->memory + data, extent, m->memory + workspace,
                  &m->safer_profile, mode, decode);
    m->last_cipher_data = data;
    m->last_cipher_length = length;
    m->last_cipher_mode = mode;
    memcpy(m->last_cipher_output, m->memory + data,
           extent < sizeof(m->last_cipher_output) ? extent : sizeof(m->last_cipher_output));
    if (decode) ++m->rom_decode_calls;
    else ++m->rom_encode_calls;
    rom_return(cpu);
}

static void software_interrupt(struct ARMCore *cpu, int value) {
    Machine *m = owner(cpu);
    if (m->rom_hle && m->pc == 0x00840000 && value == 0xFF) {
        /* Entry 0 has the memcpy ABI at the observed flash call sites. */
        uint32_t destination = cpu->gprs[0], source = cpu->gprs[1], length = cpu->gprs[2];
        if (length > FLASH_SIZE)
            stop_at(m, "invalid_rom_copy_length", "copy", source, 0, length);
        fprintf(stderr, "[rom-hle] inferred memcpy dst=%08x src=%08x length=%u\n",
                destination, source, length);
        for (uint32_t i = 0; i < length; ++i)
            write_bus(m, destination + i, 1, read_bus(m, source + i, 1));
        ++m->rom_copy_calls;
        rom_return(cpu);
        return;
    }
    if (m->tds6_safer && value == 0xFF && m->pc == 0x0084000E) {
        rom_safer(m, 1);
        return;
    }
    if (m->tds6_safer && value == 0xFF && m->pc == 0x00840010) {
        rom_safer(m, 0);
        return;
    }
    if (m->rom_hle && value == 0xFF && m->pc == 0x00840016) {
        /* The caller passes four flash limits and ignores the return value.
           Flash is already decoded by prepare.py; retain the requested limits
           without configuring the absent on-chip decryptor. */
        for (unsigned i = 0; i < 4; ++i) m->rom_flash_limits[i] = cpu->gprs[i];
        ++m->rom_flash_limit_calls;
        fprintf(stderr, "[rom-hle] inferred flash limits %08x %08x %08x %08x; hardware side effects unverified\n",
                m->rom_flash_limits[0], m->rom_flash_limits[1],
                m->rom_flash_limits[2], m->rom_flash_limits[3]);
        rom_return(cpu);
        return;
    }
    if (m->rom_hle && value == 0xFF && m->pc == 0x00840014) {
        /* TriX's fsig_clone returns when these engine preconditions are absent.
           No signature verdict is supplied by this inactive-engine path. */
        uint32_t check1 = read_bus(m, 0x0600C82A, 2);
        uint32_t check2 = read_bus(m, 0x0600C828, 2);
        uint32_t check3 = read_bus(m, 0x0600C826, 2);
        ++m->rom_fsig_calls;
        if (!check1 && (check2 + check3))
            stop_at(m, "fsig_engine_unimplemented", "call", m->pc | 1u, 0, cpu->gprs[0]);
        fprintf(stderr, "[rom-hle] FSIG engine inactive (%04x %04x %04x); signature not evaluated\n",
                check1, check2, check3);
        rom_return(cpu);
        return;
    }
    if (m->rom_hle && value == 0xFF && m->pc == 0x0084001C) {
        /* TriX standalone/fsig/fsig_asm.s uses 0x100 for this development
           ROM profile. This is an assumed hardware status, not a ROM capture. */
        cpu->gprs[0] = m->rom_status_flags;
        ++m->rom_status_calls;
        fprintf(stderr, "[rom-hle] development status flags=%08x; unverified\n", m->rom_status_flags);
        rom_return(cpu);
        return;
    }
    if (m->rom_hle && value == 0xFF && in_range(m->pc, 2, 0x00840000, 0x44))
        stop_at(m, "unimplemented_rom_service", "call", m->pc | 1u, 0, cpu->gprs[ARM_LR]);
    if (!owner(cpu)->legacy_reset_state)
        stop_at(owner(cpu), "missing_boot_rom_vectors", "swi", owner(cpu)->pc, 0, (uint32_t)value);
    ARMRaiseSWI(cpu);
}
static void breakpoint(struct ARMCore *cpu, int value) {
    stop_at(owner(cpu), "breakpoint", "execute", owner(cpu)->pc, 0, (uint32_t)value);
}
static void illegal(struct ARMCore *cpu, uint32_t value) {
    stop_at(owner(cpu), "illegal_or_unimplemented_instruction", "execute", owner(cpu)->pc, 0, value);
}
static void component_init(void *cpu, struct mCPUComponent *component) { (void)cpu; (void)component; }
static struct mCPUComponent master = {0, component_init, NULL};

static void initialize(Machine *m) {
    struct ARMCore *cpu = &m->cpu;
    cpu->memory = (struct ARMMemory){
        .activeRegion = (const uint32_t *)m->memory, .activeMask = ADDRESS_SPACE - 1,
        .load32 = load32, .load16 = load16, .load8 = load8,
        .store32 = store32, .store16 = store16, .store8 = store8,
        .loadMultiple = load_multiple, .storeMultiple = store_multiple,
        .stall = stall, .setActiveRegion = active_region, .accessSource = mACCESS_PROGRAM,
    };
    cpu->irqh = (struct ARMInterruptHandler){
        .reset = reset, .processEvents = events, .swi16 = software_interrupt,
        .swi32 = software_interrupt, .bkpt16 = breakpoint, .bkpt32 = breakpoint,
        .hitIllegal = illegal, .hitStub = illegal, .readCPSR = read_cpsr,
    };
    ARMSetComponents(cpu, &master, 0, NULL);
    ARMInit(cpu);
    if (m->legacy_reset_state) {
        /* Boot-ROM handoff substitute: LDR PC,[PC,#0x18] uses the firmware's
           vector table at 0x20. This is synthetic bootstrap code, not a ROM dump. */
        for (unsigned address = 0; address < 0x20; address += 4) {
            m->memory[address] = 0xE5;
            m->memory[address + 1] = 0x9F;
            m->memory[address + 2] = 0xF0;
            m->memory[address + 3] = 0x18;
        }
    }
    if (m->rom_hle) {
        for (uint32_t address = 0x00840000; address < 0x00840048; address += 2) {
            m->memory[address] = 0xDF;
            m->memory[address + 1] = 0xFF;
        }
    }
    ARMReset(cpu);
    ARMSetPrivilegeMode(cpu, MODE_SUPERVISOR);
    cpu->cpsr.packed = MODE_SUPERVISOR | 0xC0;
    cpu->gprs[ARM_PC] = FLASH_BASE + 0x100;
    ARMWritePC(cpu);
}

static int provision_virtual_identity(Machine *m, const char *imei) {
    if (!m->tds6_safer || strlen(imei) != 15) {
        fprintf(stderr, "Virtual IMEI requires fifteen digits and the TDS6 cipher profile\n");
        return 0;
    }
    for (unsigned i = 0; i < 15; ++i) {
        if (imei[i] < '0' || imei[i] > '9') {
            fprintf(stderr, "Virtual IMEI must contain only digits\n");
            return 0;
        }
    }
    uint8_t identity[8] = {0};
    identity[0] = (uint8_t)((imei[0] - '0') << 4);
    for (unsigned i = 1; i < 7; ++i)
        identity[i] = (uint8_t)(((imei[2 * i] - '0') << 4) | (imei[2 * i - 1] - '0'));
    identity[7] = (uint8_t)(imei[13] - '0');
    for (unsigned i = 0; i < 4; ++i)
        m->uem_otp[i] = (uint16_t)identity[2 * i] << 8 | identity[2 * i + 1];
    uint8_t factory[40], work[TDS6_SAFER_WORKSPACE] = {0};
    memset(factory, 0xFF, sizeof(factory));
    memcpy(factory + 13, identity, sizeof(identity));
    memset(factory + 21, 0, 8);
    unsigned sum = 0;
    for (unsigned i = 0; i < 38; ++i) sum += factory[i];
    factory[38] = (uint8_t)(sum >> 8);
    factory[39] = (uint8_t)sum;
    tds6_safer_cbc(factory, sizeof(factory), work, &m->safer_profile, 0x20, 0);
    memcpy(m->memory + FLASH_BASE + 0x3A, factory, sizeof(factory));
    memcpy(m->memory + 0x0900003A, factory, sizeof(factory));
    memcpy(m->virtual_imei, imei, sizeof(m->virtual_imei));
    fprintf(stderr, "[virtual-device] provisioned development factory identity %s in memory\n", imei);
    return 1;
}

static void report(const Machine *m) {
    printf("{\n  \"status\": \"development\",\n");
    printf("  \"cpu\": \"mGBA ARM7TDMI, big endian\",\n");
    printf("  \"start\": \"flash entry 0x01000100; boot ROM skipped\",\n");
    printf("  \"provisional_models\": [\"register readback\", \"immediate PLL lock\", "
           "\"empty STI endpoints\", \"1 MiB RAM window\", \"16 MiB flash window\", "
           "\"8 KiB shared RAM at 0x07000000\", \"8 KiB boot RAM at 0x007fe000\"],\n");
    printf("  \"legacy_reset_state\": %s,\n", m->legacy_reset_state ? "true" : "false");
    printf("  \"synthetic_boot_vectors\": %s,\n", m->legacy_reset_state ? "true" : "false");
    printf("  \"boot_rom_bytes\": %u,\n", m->rom_size);
    printf("  \"virtual_imei\": \"%s\",\n", m->virtual_imei);
    printf("  \"inferred_rom_copy_calls\": %u,\n", m->rom_copy_calls);
    printf("  \"rom_fsig\": {\"calls\": %u, \"signature_evaluated\": false},\n", m->rom_fsig_calls);
    printf("  \"lcd_bus\": {\"commands\": %u, \"data_writes\": %u, "
           "\"controller_id\": \"%02x%02x%02x\", \"profile\": \"S6B33BD-compatible\"},\n",
           m->lcd_commands, m->lcd_data_bytes, m->lcd_id[0], m->lcd_id[1], m->lcd_id[2]);
    printf("  \"rom_status\": {\"calls\": %u, \"flags\": \"0x%08x\", "
           "\"source\": \"unverified TriX development profile\"},\n", m->rom_status_calls, m->rom_status_flags);
    printf("  \"flash_operations\": {\"programmed_words\": %u, \"erased_blocks\": %u},\n",
           m->flash_programs, m->flash_erases);
    printf("  \"inferred_rom_flash_limits\": {\"calls\": %u, \"values\": [\"0x%08x\", "
           "\"0x%08x\", \"0x%08x\", \"0x%08x\"], \"hardware_side_effects_verified\": false},\n",
           m->rom_flash_limit_calls, m->rom_flash_limits[0], m->rom_flash_limits[1],
           m->rom_flash_limits[2], m->rom_flash_limits[3]);
    printf("  \"tds6_safer\": {\"enabled\": %s, \"asic_compatibility_verified\": false, "
           "\"zero_key_profile\": %s, \"decode_calls\": %u, \"encode_calls\": %u},\n",
           m->tds6_safer ? "true" : "false", m->tds6_zero_key_profile ? "true" : "false",
           m->rom_decode_calls, m->rom_encode_calls);
    if (m->rom_decode_calls || m->rom_encode_calls) {
        printf("  \"last_cipher_call\": {\"data\": \"0x%08x\", \"length\": %u, "
               "\"mode\": \"0x%02x\", \"output_prefix\": \"",
               m->last_cipher_data, m->last_cipher_length, m->last_cipher_mode);
        unsigned count = m->last_cipher_length < sizeof(m->last_cipher_output) ?
                         m->last_cipher_length : sizeof(m->last_cipher_output);
        for (unsigned i = 0; i < count; ++i) printf("%02x", m->last_cipher_output[i]);
        printf("\"},\n");
    }
    printf("  \"steps_started\": %" PRIu64 ",\n", m->steps);
    printf("  \"clock_ticks_32768_hz\": %" PRIu64 ",\n", m->clock_ticks_q32 >> 32);
    printf("  \"interrupts\": {\"irq_deliveries\": %u, \"timer2_matches\": %u, "
           "\"inferred_coarse_timer_events\": %u, \"group2_enabled\": \"0x%04x\", \"group2_pending\": \"0x%04x\"},\n",
           m->irq_deliveries, m->timer2_matches, m->timer2_coarse_events,
           m->irq_enabled[2], m->irq_pending[2]);
    printf("  \"timer2\": {\"armed\": %s, \"compare\": %u, \"prescaler\": %u, "
           "\"deadline_ticks\": %" PRIu64 "},\n", m->timer2_armed ? "true" : "false",
           m->timer2_compare, m->timer2_prescaler, m->timer2_deadline);
    printf("  \"mdi_peer\": {\"enabled\": %s, \"registration_sent\": %s, "
           "\"presence_announcements\": %u, \"tx_words_consumed\": %u, \"entity_unavailable_replies\": %u, "
           "\"mtc_ready_sent\": %s, \"mtc_responses\": %u, \"version_replies\": %u},\n",
           m->mdi_peer ? "true" : "false", m->mdi_registration_sent ? "true" : "false",
           m->mdi_announcements, m->mdi_tx_words, m->mdi_unavailable_replies,
           m->mdi_mtc_ready ? "true" : "false", m->mdi_mtc_responses, m->mdi_version_replies);
    printf("  \"sim_detect_high\": %s,\n", m->sim_detect_high ? "true" : "false");
    if (m->virtual_sim_enabled)
        printf("  \"virtual_sim\": {\"commands\": %u, \"uart_rx_armed\": %u, \"transfer_count\": %u, "
               "\"uem_control\": %u, \"uem_pending\": %u, \"uem_mask\": %u, "
               "\"fiq_enabled\": %u, \"fiq_pending\": %u},\n",
               m->virtual_sim.commands, m->sim_rx_armed, m->sim_transfer_count,
               m->cbus_registers[1][8], m->cbus_registers[1][0x15], m->cbus_registers[1][0x16],
               m->irq_enabled[0], m->irq_pending[0]);
    printf("  \"sim_interface\": {\"control\": %u, \"status\": %u, "
           "\"receive_timeouts\": %u, \"fiq_deliveries\": %u, \"timeout_timing_verified\": false},\n",
           m->sim_control, m->sim_status, m->sim_rx_timeouts, m->fiq_deliveries);
    printf("  \"lcd_dma\": {\"bytes\": %" PRIu64 ", \"channel_completions\": [%u, %u], "
           "\"serial_clock_hz\": %u, \"serial_bits_per_byte\": 9, \"cycle_timing_verified\": false},\n",
           m->dma_lcd_bytes, m->dma_completions[0], m->dma_completions[1], m->lcd_serial_hz);
    printf("  \"keypad\": {\"pressed_matrix\": %u, \"changes\": %u},\n",
           m->keypad_pressed, m->keypad_changes);
    printf("  \"audio_dac\": {\"rate_hz\": %u, \"samples\": %" PRIu64
           ", \"nonzero_samples\": %" PRIu64 ", \"dma_cycles\": %u},\n",
           DAC_RATE, m->dac_samples, m->dac_nonzero_samples, m->dma_completions[1]);
    printf("  \"call_timer\": {\"enabled\": %s, \"divider\": %u, \"ticks\": %" PRIu64 "},\n",
           m->call_timer_enabled ? "true" : "false", m->call_timer_divider, m->call_timer_ticks);
    printf("  \"storage\": {\"persistent\": %s, \"loaded\": %s, \"saves\": %u, \"dirty\": %s},\n",
           m->nvram.path ? "true" : "false", m->nvram.loaded ? "true" : "false",
           m->nvram.saves, m->nvram_dirty ? "true" : "false");
    printf("  \"stop_reason\": \"%s\",\n", m->reason ? m->reason : "instruction_limit");
    printf("  \"pc\": \"0x%08" PRIx32 "\",\n", m->pc);
    printf("  \"access\": {\"operation\": \"%s\", \"address\": \"0x%08" PRIx32
           "\", \"size\": %u, \"value\": \"0x%08" PRIx32 "\"},\n",
           m->operation ? m->operation : "none", m->address, m->width, m->value);
    printf("  \"registers\": [");
    for (unsigned i = 0; i < 16; ++i)
        printf("%s\"0x%08" PRIx32 "\"", i ? ", " : "", (uint32_t)m->cpu.gprs[i]);
    printf("],\n  \"cpsr\": \"0x%08" PRIx32 "\",\n", (uint32_t)m->cpu.cpsr.packed);
    printf("  \"recent_mmio\": [\n");
    uint64_t io_start = m->mmio_count > HISTORY ? m->mmio_count - HISTORY : 0;
    for (uint64_t index = io_start; index < m->mmio_count; ++index) {
        const BusEvent *event = &m->mmio_history[index % HISTORY];
        printf("    {\"pc\": \"0x%08" PRIx32 "\", \"operation\": \"%s\", "
               "\"address\": \"0x%08" PRIx32 "\", \"size\": %u, \"value\": \"0x%08" PRIx32 "\"}%s\n",
               event->pc, event->write ? "write" : "read", event->address, event->width,
               event->value, index + 1 < m->mmio_count ? "," : "");
    }
    printf("  ],\n");
    printf("  \"recent_instructions\": [\n");
    uint64_t start = m->no_history ? m->steps : m->steps > HISTORY ? m->steps - HISTORY : 0;
    for (uint64_t index = start; index < m->steps; ++index) {
        unsigned slot = index % HISTORY;
        printf("    {\"pc\": \"0x%08" PRIx32 "\", \"state\": \"%s\", \"opcode\": \"0x%08" PRIx32 "\"}%s\n",
               m->history[slot], m->states[slot] ? "thumb" : "arm", m->opcodes[slot],
               index + 1 < m->steps ? "," : "");
    }
    printf("  ]\n}\n");
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);  /* A disconnected live audio sink must not kill the phone. */
    stop_requested = 0;
    signal(SIGTERM, request_stop);
    signal(SIGINT, request_stop);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s prepared-flash.bin [instruction-limit; 0=unlimited] [--realtime] [--legacy-reset-state] [--dump-ram=FILE] [--raw-flash=FILE] [--boot-rom=FILE | --rom-hle [--tds6-safer=FILE]]\n", argv[0]);
        return 1;
    }
    uint64_t limit = 1000000;
    unsigned legacy_reset_state = 0;
    const char *ram_output = NULL;
    const char *raw_flash = NULL;
    const char *boot_rom = NULL;
    const char *tds6 = NULL;
    const char *lcd_trace = NULL;
    const char *api_output = NULL;
    const char *virtual_imei = NULL;
    const char *nvram_seed = NULL;
    const char *nvram_path = NULL;
    unsigned rom_hle = 0;
    unsigned power_key_ms = 800;
    unsigned mdi_peer = 0;
    unsigned sim_detect_high = 0;
    unsigned virtual_sim_enabled = 0;
    unsigned no_sim = 0;
    unsigned stdin_keys = 0;
    unsigned realtime = 0;
    unsigned no_history = 0;
    for (int arg = 2; arg < argc; ++arg) {
        if (!strcmp(argv[arg], "--legacy-reset-state")) {
            legacy_reset_state = 1;
            continue;
        }
        if (!strncmp(argv[arg], "--dump-ram=", 11)) {
            ram_output = argv[arg] + 11;
            if (!*ram_output) { fprintf(stderr, "RAM output path is empty\n"); return 1; }
            struct stat source, destination;
            if (!stat(argv[1], &source) && !stat(ram_output, &destination) &&
                source.st_dev == destination.st_dev && source.st_ino == destination.st_ino) {
                fprintf(stderr, "RAM output must differ from the input flash\n");
                return 1;
            }
            continue;
        }
        if (!strncmp(argv[arg], "--raw-flash=", 12)) {
            raw_flash = argv[arg] + 12;
            continue;
        }
        if (!strncmp(argv[arg], "--nvram-seed=", 13)) {
            nvram_seed = argv[arg] + 13;
            if (!*nvram_seed) { fprintf(stderr, "NVRAM seed path is empty\n"); return 1; }
            continue;
        }
        if (!strncmp(argv[arg], "--nvram=", 8)) {
            nvram_path = argv[arg] + 8;
            if (!*nvram_path) { fprintf(stderr, "Storage path is empty\n"); return 1; }
            continue;
        }
        if (!strncmp(argv[arg], "--boot-rom=", 11)) {
            boot_rom = argv[arg] + 11;
            continue;
        }
        if (!strcmp(argv[arg], "--rom-hle")) {
            rom_hle = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--mdi-peer")) {
            mdi_peer = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--sim-detect-high")) {
            sim_detect_high = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--virtual-sim")) {
            virtual_sim_enabled = 1;
            continue;
        }
        /* Hard off switch for the whole SIM model: no ATR, no reply, no SIMIF
           status bits and no SIM interrupt, i.e. the same view a board with
           the SIMIF block left unmodelled would give the firmware. Use it to
           boot without any SIM involvement at all. */
        if (!strcmp(argv[arg], "--no-sim")) {
            no_sim = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--stdin-keys")) {
            stdin_keys = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--realtime")) {
            realtime = 1;
            continue;
        }
        if (!strcmp(argv[arg], "--no-history")) {
            no_history = 1;
            continue;
        }
        if (!strncmp(argv[arg], "--tds6-safer=", 13)) {
            tds6 = argv[arg] + 13;
            continue;
        }
        if (!strncmp(argv[arg], "--lcd-trace=", 12)) {
            lcd_trace = argv[arg] + 12;
            continue;
        }
        if (!strncmp(argv[arg], "--dump-api=", 11)) {
            api_output = argv[arg] + 11;
            continue;
        }
        if (!strncmp(argv[arg], "--virtual-imei=", 15)) {
            virtual_imei = argv[arg] + 15;
            continue;
        }
        if (!strncmp(argv[arg], "--power-key-ms=", 15)) {
            char *end;
            errno = 0;
            unsigned long duration = strtoul(argv[arg] + 15, &end, 10);
            if (errno || end == argv[arg] + 15 || *end || duration > 60000) {
                fprintf(stderr, "Power-key duration must be between 0 and 60000 milliseconds\n");
                return 1;
            }
            power_key_ms = (unsigned)duration;
            continue;
        }
        char *end;
        errno = 0;
        uint64_t parsed_limit = strtoull(argv[arg], &end, 10);
        if (errno || end == argv[arg] || *end || argv[arg][0] == '-' || parsed_limit > 10000000000ull) {
            fprintf(stderr, "Instruction limit must be between 0 and 10000000000 (0 = unlimited)\n");
            return 1;
        }
        limit = parsed_limit ? parsed_limit : UINT64_MAX;
    }
    if ((rom_hle || tds6) && boot_rom) {
        fprintf(stderr, "Choose a boot ROM image or the inferred ROM service, not both\n");
        return 1;
    }
    if (tds6 && !rom_hle) {
        fprintf(stderr, "The experimental TDS6 model requires --rom-hle\n");
        return 1;
    }
    FILE *input = fopen(argv[1], "rb");
    if (!input) { perror(argv[1]); return 1; }
    Machine *m = calloc(1, sizeof(*m));
    if (!m) { fclose(input); return 1; }
    m->legacy_reset_state = legacy_reset_state;
    m->rom_hle = rom_hle;
    m->mdi_peer = mdi_peer;
    m->sim_detect_high = sim_detect_high;
    m->virtual_sim_enabled = virtual_sim_enabled;
    if (no_sim || getenv("RH105_NO_SIM")) {
        m->virtual_sim_enabled = 0;
        m->sim_detect_high = 0; /* Empty slot: the firmware sees no card. */
    }
    if (m->virtual_sim_enabled) {
        m->sim_detect_high = 1;
        virtual_sim_init(&m->virtual_sim);
    }
    m->stdin_keys = stdin_keys;
    m->realtime = realtime;
    m->rom_status_flags = 0x100;
    m->cbus_log_limit = 256;
    if (getenv("RH105_CBUS_LOG")) m->cbus_log_limit = (unsigned)strtoul(getenv("RH105_CBUS_LOG"), NULL, 0);
    m->strict_registers = !legacy_reset_state || getenv("RH105_STRICT_REGISTERS") != NULL;
    /* Environment is configuration, not a bus operation. Cache these once:
       RAM traffic alone reaches tens of millions of accesses per second. */
    m->trace_keypad = getenv("RH105_KEY_TRACE") != NULL;
    m->trace_scan = getenv("RH105_KP_SCAN") != NULL;
    m->trace_uif = getenv("RH105_UIF_TRACE") != NULL;
    m->trace_ram = getenv("RH105_WATCH_RAM") != NULL;
    m->trace_pc = getenv("RH105_PC_TRACE") != NULL;
    m->trace_progress = getenv("RH105_PROGRESS") != NULL;
    m->no_history = no_history;
    m->trace_lcd_timing = getenv("RH105_LCD_TIMING") != NULL;
    /* RH105_POKE="466=1,470=0" forces big-endian halfwords on every event
       tick. Diagnostic only: it answers "is this field the gate that stops the
       UI?" without patching firmware code. It has to be reapplied because the
       firmware owns and rewrites these fields. */
    const char *poke = getenv("RH105_POKE");
    while (poke && *poke && m->poke_count < sizeof(m->pokes) / sizeof(m->pokes[0])) {
        char *end;
        unsigned long address = strtoul(poke, &end, 16);
        if (end == poke || *end != '=') break;
        poke = end + 1;
        unsigned long value = strtoul(poke, &end, 0);
        if (end == poke) break;
        m->pokes[m->poke_count].address = (uint32_t)address;
        m->pokes[m->poke_count].value = (uint32_t)value;
        ++m->poke_count;
        poke = *end == ',' ? end + 1 : end;
    }
    m->lcd_serial_hz = 2500000;
    const char *lcd_hz = getenv("RH105_LCD_HZ");
    if (lcd_hz) {
        char *end;
        errno = 0;
        unsigned long rate = strtoul(lcd_hz, &end, 10);
        if (errno || end == lcd_hz || *end || rate < 100000 || rate > 13000000) {
            fprintf(stderr, "RH105_LCD_HZ must be between 100000 and 13000000\n");
            fclose(input); free(m); return 1;
        }
        m->lcd_serial_hz = (uint32_t)rate;
    }
    m->audio_out = NULL;
    m->lcd_id[0] = 0xFE;
    m->lcd_id[1] = 0x89;
    m->lcd_id[2] = 0x0E;
    if (tds6) {
        if (!tds6_safer_load_profile(tds6, &m->safer_profile)) {
            fclose(input); free(m); return 1;
        }
        m->tds6_safer = 1;
        unsigned nonzero = 0;
        for (unsigned i = 0; i < sizeof(m->safer_profile.root); ++i) nonzero |= m->safer_profile.root[i];
        for (unsigned i = 0; i < sizeof(m->safer_profile.salt); ++i) nonzero |= m->safer_profile.salt[i];
        m->tds6_zero_key_profile = !nonzero;
        fprintf(stderr, "[tds6-safer] Loaded TDS6 defaults%s; Nokia 1208 ASIC compatibility unverified\n",
                nonzero ? "" : " (zero-filled root key and salts)");
    }
    m->system_type = 0x03A6;
    m->timer2_prescaler = 0x1F;
    m->timer2_base = 0x8000;
    m->clock_step_q32 = (32768ull << 32) / 13000000;
    m->events_tick = UINT64_MAX;   /* first pass runs the whole model */
    m->power_key_release_tick = (uint64_t)power_key_ms * 32768 / 1000;
    m->memory = calloc(1, ADDRESS_SPACE);
    if (!m->memory) { fclose(input); free(m); return 1; }
    memset(m->memory + FLASH_BASE, 0xFF, FLASH_SIZE);
    size_t size = fread(m->memory + FLASH_BASE, 1, FLASH_SIZE, input);
    int extra = fgetc(input);
    if (ferror(input) || extra != EOF || size < 0x104 || m->memory[FLASH_BASE + 0x100] != 0xEA) {
        fprintf(stderr, "Expected a decrypted RH-105 flash image no larger than 16 MiB\n");
        fclose(input); free(m->memory); free(m); return 1;
    }
    fclose(input);
    if (raw_flash) {
        input = fopen(raw_flash, "rb");
        if (!input) { perror(raw_flash); free(m->memory); free(m); return 1; }
        memset(m->memory + 0x09000000, 0xFF, FLASH_SIZE);
        size_t raw_size = fread(m->memory + 0x09000000, 1, FLASH_SIZE, input);
        extra = fgetc(input);
        if (ferror(input) || extra != EOF || raw_size != size) {
            fprintf(stderr, "Raw and decrypted flash image sizes must match\n");
            fclose(input); free(m->memory); free(m); return 1;
        }
        fclose(input);
        m->raw_flash_loaded = 1;
    }
    if (!nvram_open(&m->nvram, nvram_path, m->memory + NVRAM_BASE)) {
        free(m->memory); free(m); return 1;
    }
    if (!m->nvram.loaded && nvram_seed &&
        !nvram_load_image(nvram_seed, m->memory + NVRAM_BASE)) {
        nvram_close(&m->nvram); free(m->memory); free(m); return 1;
    }
    if (m->nvram.loaded || nvram_seed) {
        if (m->raw_flash_loaded)
            memcpy(m->memory + NVRAM_BASE + 0x08000000, m->memory + NVRAM_BASE, NVRAM_SIZE);
        fprintf(stderr, "[nvram] loaded %s storage into the virtual flash\n",
                m->nvram.loaded ? "saved handset" : "factory");
    }
    m->nvram_dirty = !m->nvram.loaded;
    m->nvram_next_save = 2 * 32768;
    if (boot_rom) {
        input = fopen(boot_rom, "rb");
        if (!input) { perror(boot_rom); free(m->memory); free(m); return 1; }
        size_t rom_size = fread(m->memory + 0x00800000, 1, 0x100000, input);
        extra = fgetc(input);
        if (ferror(input) || extra != EOF || rom_size != 0x100000) {
            fprintf(stderr, "Expected a 1 MiB MCU ROM image mapped at 0x00800000\n");
            fclose(input); free(m->memory); free(m); return 1;
        }
        fclose(input);
        m->rom_size = (uint32_t)rom_size;
    }
    if (virtual_imei && !provision_virtual_identity(m, virtual_imei)) {
        free(m->memory); free(m); return 1;
    }
    if (lcd_trace) {
        m->lcd_trace = fopen(lcd_trace, "wb");
        /* A large buffer keeps the per-pixel writes cheap; events() flushes
           it on every panel update so a live viewer stays responsive. */
        if (m->lcd_trace) setvbuf(m->lcd_trace, NULL, _IOFBF, 1u << 16);
        if (!m->lcd_trace || fwrite("RH105LCD\1", 1, 9, m->lcd_trace) != 9) {
            perror(lcd_trace);
            if (m->lcd_trace) fclose(m->lcd_trace);
            free(m->memory); free(m); return 1;
        }
    }
    int trace_keypad = m->trace_keypad;
    int trace_scan = m->trace_scan;
    int trace_ui_keys = getenv("RH105_UI_KEY_TRACE") != NULL;
    int instrumented = trace_keypad || trace_scan || trace_ui_keys ||
                       getenv("RH105_FIRMWARE_TRACE") || getenv("RH105_TRACE_PC");
    int fast_wait = !instrumented && !m->trace_pc && !m->trace_ram &&
                    !getenv("RH105_NO_FAST_WAIT");
    int record_history = !m->no_history;
    if (!setjmp(m->stop)) {
        initialize(m);
        m->realtime_epoch_ns = monotonic_ns();
        for (; m->steps < limit;) {
            m->pc = (uint32_t)m->cpu.gprs[ARM_PC] - (m->cpu.cpsr.t ? 2u : 4u);
            if (m->pc - m->fetch_base > m->fetch_size - (m->cpu.cpsr.t ? 2u : 4u))
                stop_at(m, "unmodeled_instruction_memory", "fetch", m->pc, 0, 0);
            if (fast_wait && m->pc == 0x0000132a && countdown_fastforward(m, limit))
                continue;
            /* The core already fetched and byte-swapped this instruction.
               Record what it executes, not a second byte-by-byte bus fetch. */
            uint32_t opcode = m->cpu.prefetch[0];
            unsigned width = m->cpu.cpsr.t ? 2 : 4;
            if (record_history) {
                unsigned slot = m->steps % HISTORY;
                m->history[slot] = m->pc;
                m->states[slot] = m->cpu.cpsr.t;
                m->opcodes[slot] = opcode;
            }
            ++m->steps;
            /* Diagnostic firmware probes are opt-in. Reset/assert traps are
               still unconditional; normal execution skips the other probes. */
            if (instrumented || m->pc == 0x011F0900 || m->pc == 0x0113AF8C) {
            {
                static uint64_t trace_target;
                static unsigned trace_max = 64;
                static int trace_init;
                static unsigned trace_count;
                if (!trace_init) {
                    const char *wanted = getenv("RH105_TRACE_PC");
                    const char *max = getenv("RH105_TRACE_MAX");
                    trace_init = 1;
                    trace_target = wanted ? strtoull(wanted, NULL, 16) : 0;
                    if (max) trace_max = (unsigned)strtoul(max, NULL, 10);
                }
                if (trace_target && m->pc == (uint32_t)trace_target && trace_count++ < trace_max)
                    fprintf(stderr, "[trace] pc=%08x r0=%08x r1=%08x r2=%08x r3=%08x r4=%08x r5=%08x "
                                    "sp=%08x lr=%08x tick=%" PRIu64 "\n",
                            m->pc, (uint32_t)m->cpu.gprs[0], (uint32_t)m->cpu.gprs[1],
                            (uint32_t)m->cpu.gprs[2], (uint32_t)m->cpu.gprs[3],
                            (uint32_t)m->cpu.gprs[4], (uint32_t)m->cpu.gprs[5],
                            (uint32_t)m->cpu.gprs[ARM_SP], (uint32_t)m->cpu.gprs[ARM_LR],
                            m->clock_ticks_q32 >> 32);
            }
            if (trace_scan) {
                static uint32_t seen[8];
                static const uint32_t watch[8] = {0x01130CF8, 0x01130D30, 0x01130D2A, 0x01130D56,
                                                  0x01130DB6, 0x01130D5C, 0x01130DD4, 0x01130DFA};
                for (unsigned wi = 0; wi < 8; ++wi) {
                    if (m->pc != watch[wi] || seen[wi]++) continue;
                    fprintf(stderr, "[kp-wp] hit %08x lr=%08x r0=%08x r4=%08x r7=%08x tick=%" PRIu64 "\n",
                            m->pc, (uint32_t)m->cpu.gprs[ARM_LR], (uint32_t)m->cpu.gprs[0],
                            (uint32_t)m->cpu.gprs[4], (uint32_t)m->cpu.gprs[7],
                            m->clock_ticks_q32 >> 32);
                }
            }
            /* Observe the real firmware UI queue, including callers that
               bypass the thin press/release wrappers at 0108f406/408. */
            if (trace_keypad && m->pc == 0x0108F326)
                fprintf(stderr, "[firmware-key] code=%02x state=%s tick=%" PRIu64
                        " lcd_records=%" PRIu64 "\n",
                        (unsigned)m->cpu.gprs[0] & 255,
                        m->cpu.gprs[0] & 0x100 ? "up" : "down", m->clock_ticks_q32 >> 32,
                        (uint64_t)m->lcd_commands + m->lcd_data_bytes);
            if (trace_scan && m->pc == 0x011F2716) {
                static uint32_t last_lr;
                uint32_t lr = (uint32_t)m->cpu.gprs[ARM_LR];
                if (lr != last_lr) {
                    last_lr = lr;
                    fprintf(stderr, "[kp-scan-caller] lr=%08x tick=%" PRIu64 "\n",
                            lr, m->clock_ticks_q32 >> 32);
                }
            }
            if (trace_scan && m->pc == 0x011F27C0)
                fprintf(stderr, "[kp-scan-exit] keys=%08x tick=%" PRIu64 "\n",
                        (uint32_t)m->cpu.gprs[5], m->clock_ticks_q32 >> 32);
            if (m->pc == 0x011ED790)
                fprintf(stderr, "[fiq-handler] slot=%u handler=%08x source=%u\n",
                        (unsigned)m->cpu.gprs[0], (uint32_t)m->cpu.gprs[1], (unsigned)m->cpu.gprs[2]);
            if (m->pc == 0x0118701A)
                fprintf(stderr, "[sim-state] old=%u new=%u caller=%08x\n",
                        (unsigned)m->cpu.gprs[1], (unsigned)m->cpu.gprs[2],
                        (uint32_t)m->cpu.gprs[ARM_LR]);
            if (m->pc == 0x01186B3A || m->pc == 0x01186B74)
                fprintf(stderr, "[sim-control] method=%s caller=%08x\n",
                        m->pc == 0x01186B3A ? "c012" : "c014", (uint32_t)m->cpu.gprs[ARM_LR]);
            if (m->pc == 0x01133D90 && in_range((uint32_t)m->cpu.gprs[0], 10, 0, RAM_SIZE)) {
                uint32_t packet = m->cpu.gprs[0];
                uint8_t resource = m->memory[packet + 3];
                if (m->pn_resource_traces[resource]++ < 6) {
                    fprintf(stderr, "[pn-send] task=%u caller=%08x bytes:",
                            m->memory[0xE92F2], (uint32_t)m->cpu.gprs[ARM_LR]);
                    unsigned length = 6u + memory16(m, packet + 4);
                    if (length > 24) length = 24;
                    for (unsigned i = 0; i < length && packet + i < RAM_SIZE; ++i)
                        fprintf(stderr, " %02x", m->memory[packet + i]);
                    fputc('\n', stderr);
                }
            }
            if (m->pc == 0x011DE886 && in_range((uint32_t)m->cpu.gprs[0], 4, 0, RAM_SIZE)) {
                uint32_t packet = m->cpu.gprs[0];
                fprintf(stderr, "[isa-send] message=%02x length=%u caller=%08x task=%u\n",
                        m->memory[packet + 3], m->memory[packet + 2],
                        (uint32_t)m->cpu.gprs[ARM_LR], m->memory[0xE92F2]);
            }
            if (m->pc == 0x01133D90 && plain_memory(m, (uint32_t)m->cpu.gprs[0], 12)) {
                uint32_t packet = m->cpu.gprs[0];
                if (m->memory[packet + 1] == 0x7C && m->memory[packet + 3] >= 0xF0 &&
                    m->memory[packet + 3] <= 0xF3 && m->dsp_call_traces++ < 24) {
                    fprintf(stderr, "[dsp-call] resource=%02x message=%02x caller=%08x task=%u stack:",
                            m->memory[packet + 3], m->memory[packet + 9],
                            (uint32_t)m->cpu.gprs[ARM_LR], m->memory[0xE92F2]);
                    uint32_t stack = m->cpu.gprs[ARM_SP];
                    for (unsigned offset = 0; offset < 96 && in_range(stack + offset, 4, 0, RAM_SIZE); offset += 4) {
                        uint32_t candidate = read_bus(m, stack + offset, 4);
                        if (candidate >= FLASH_BASE && candidate < FLASH_BASE + 0x400000 && (candidate & 1))
                            fprintf(stderr, " %08x", candidate);
                    }
                    fputc('\n', stderr);
                }
            }
            if (trace_ui_keys && m->pc == 0x011F60A2 &&
                (m->clock_ticks_q32 >> 32) >= 79000 &&
                (uint32_t)m->cpu.gprs[ARM_LR] >= 0x0108E000 &&
                (uint32_t)m->cpu.gprs[ARM_LR] < 0x0108F000) {
                static unsigned key_ui_traces;
                if (key_ui_traces++ < 1024)
                    fprintf(stderr, "[ui-key-dispatch] event=%04x handler=%08x arg=%08x caller=%08x tick=%" PRIu64 "\n",
                            (unsigned)m->cpu.gprs[0], (uint32_t)m->cpu.gprs[1],
                            memory32(m, 0x23f0), (uint32_t)m->cpu.gprs[ARM_LR],
                            m->clock_ticks_q32 >> 32);
            }
            if (m->pc == 0x011F60A2 && (uint32_t)m->cpu.gprs[ARM_LR] >= 0x0108EC00 &&
                (uint32_t)m->cpu.gprs[ARM_LR] < 0x0108F000 &&
                (m->cpu.gprs[1] == 0x0108C0D5 || m->cpu.gprs[1] == 0x010CC0E7) &&
                m->ui_call_traces++ < 128)
                fprintf(stderr, "[ui-event] event=%04x handler=%08x\n", (unsigned)m->cpu.gprs[0],
                        (uint32_t)m->cpu.gprs[1]);
            if (m->pc == 0x0108E5C8 && (m->cpu.gprs[0] & 0x1FFF) >= 0x05DC &&
                (m->cpu.gprs[0] & 0x1FFF) <= 0x05EC && m->cpu.gprs[0] != 0x05E2)
                fprintf(stderr, "[ui-request] event=%04x arg1=%08x arg2=%08x arg3=%08x caller=%08x\n",
                        (unsigned)m->cpu.gprs[0], (uint32_t)m->cpu.gprs[1], (uint32_t)m->cpu.gprs[2],
                        (uint32_t)m->cpu.gprs[3], (uint32_t)m->cpu.gprs[ARM_LR]);
            if (m->pc == 0x01137FFA && m->cpu.gprs[2] >= 0xF0 && m->cpu.gprs[2] <= 0xF3 &&
                m->comm_call_traces++ < 32) {
                uint32_t object = m->cpu.gprs[1], vtable = 0, name = 0;
                if (plain_memory(m, object, 4)) vtable = read_bus(m, object, 4);
                if (vtable && plain_memory(m, vtable + 16, 4)) name = read_bus(m, vtable + 16, 4);
                fprintf(stderr, "[comm-call] resource=%02x destination=%04x object=%08x vtable=%08x caller=%08x",
                        (unsigned)m->cpu.gprs[2], (unsigned)m->cpu.gprs[0], object, vtable,
                        (uint32_t)m->cpu.gprs[ARM_LR]);
                if (name && plain_memory(m, name, 64)) fprintf(stderr, " class=%.*s", 60, (char *)m->memory + name);
                fputc('\n', stderr);
            }
            if (m->pc == 0x011F0900) {
                fprintf(stderr, "[reset] reason=%u caller=%08x\n", (uint32_t)m->cpu.gprs[0],
                        (uint32_t)m->cpu.gprs[ARM_LR]);
                stop_at(m, "firmware_reset_requested", "reset", m->pc, 0, m->cpu.gprs[0]);
            }
            if (m->pc == 0x01131C42)
                fprintf(stderr, "[startup] hardware-check status=%u\n", (uint32_t)m->cpu.gprs[0]);
            if (m->pc == 0x01131C4C) {
                uint32_t buffer = (uint32_t)m->cpu.gprs[ARM_SP] + 4;
                if (in_range(buffer, 16, 0, RAM_SIZE))
                    fprintf(stderr, "[startup] IMEI=%.*s\n", 15, (char *)m->memory + buffer);
            }
            if (m->pc == 0x0113AF8C) {
                uint32_t filename = m->cpu.gprs[0];
                char name[256];
                unsigned i = 0;
                while (i + 1 < sizeof(name) && plain_memory(m, filename + i, 1) &&
                       m->memory[filename + i] >= 32 && m->memory[filename + i] < 127) {
                    name[i] = (char)m->memory[filename + i];
                    ++i;
                }
                name[i] = 0;
                fprintf(stderr, "[assert] file=%s line=%u caller=%08x\n",
                        name, (uint32_t)m->cpu.gprs[1], (uint32_t)m->cpu.gprs[ARM_LR]);
                stop_at(m, "firmware_assertion", "assert", filename, 0, m->cpu.gprs[1]);
            }
            }
            if ((width == 2 && opcode == 0xE7FE) || (width == 4 && opcode == 0xEAFFFFFE))
                stop_at(m, "self_branch_no_device_events", "execute", m->pc, width, opcode);
            ARMRun(&m->cpu);
        }
    }
    audio_flush(m);
    int storage_failed = 0;
    if (m->nvram.path && m->nvram_dirty) {
        if (nvram_save(&m->nvram, m->memory + NVRAM_BASE)) m->nvram_dirty = 0;
        else storage_failed = 1;
    }
    if (audio_raw && audio_stream == stdout) {
        fflush(stdout);
        dup2(STDERR_FILENO, STDOUT_FILENO);  /* Keep the JSON report out of PCM stdout. */
    }
    report(m);
    if (m->lcd_trace && fclose(m->lcd_trace)) {
        perror(lcd_trace);
        free(m->memory); free(m); return 1;
    }
    if (api_output) {
        FILE *output = fopen(api_output, "wb");
        if (!output) { perror(api_output); free(m->memory); free(m); return 1; }
        size_t written = fwrite(m->memory + 0x05000000, 1, 0x10000, output);
        int failed = fclose(output);
        if (written != 0x10000 || failed) {
            fprintf(stderr, "Could not write the API RAM snapshot\n");
            free(m->memory); free(m); return 1;
        }
    }
    if (ram_output) {
        FILE *output = fopen(ram_output, "wb");
        if (!output) { perror(ram_output); free(m->memory); free(m); return 1; }
        size_t written = fwrite(m->memory, 1, RAM_SIZE, output);
        int failed = fclose(output);
        if (written != RAM_SIZE || failed) {
            fprintf(stderr, "Could not write the RAM snapshot\n");
            free(m->memory); free(m); return 1;
        }
    }
    ARMDeinit(&m->cpu);
    nvram_close(&m->nvram);
    free(m->memory);
    free(m);
    return storage_failed ? 1 : 2;
}
