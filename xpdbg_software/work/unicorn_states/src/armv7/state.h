/*
 *  Copyright (C) 2022, w212 research. <contact@w212research.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef STATE_H
#define STATE_H

#define STEP_STATES_BY 0x100
#define DEFAULT_LENGTH 0x100

struct mem_change_t_struct {
	uint64_t where;
	uint64_t size;
	void* what;
};

struct armv7_reg_state_t_struct {
	uint32_t regs[16];
};

typedef struct mem_change_t_struct mem_change_t;
typedef struct armv7_reg_state_t_struct armv7_reg_state_t;

struct armv7_state_t_struct {
	armv7_reg_state_t reg_state;
	mem_change_t mem_change;
};

typedef struct armv7_state_t_struct armv7_state_t;

struct armv7_history_t_struct {
	uint64_t length;
	uint64_t allocated_elements;
	uint64_t position;
	armv7_state_t* states;
};

typedef struct armv7_history_t_struct armv7_history_t;

#endif
