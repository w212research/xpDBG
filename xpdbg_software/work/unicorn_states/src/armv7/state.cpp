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

#include "state.h"

armv7_history_t* armv7_push_new_state(armv7_history_t* history,
									  armv7_state_t state,
								  	  bool to_end = true) {
	/*
	 *  it's assumed that history was allocated with malloc and co, otherwise
	 *  issues will arise
	 */
	uint64_t length = history->length;
	uint64_t allocated_elements = history->allocated_elements;
	uint64_t position = history->position;
	uint64_t states = history->states;

	while (length >= allocated_elements) {
		allocated_elements += STEP_STATES_BY;
		states = (armv7_state_t*)realloc(states, allocated_elements);
	}

	/*
	 *  states should be large enough now
	 */

	states[length] = state;
	length++;

	history->length = length;
	history->allocated_elements = allocated_elements;
	history->position = position;
	history->states = states;

	return history;
}
