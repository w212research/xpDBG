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
