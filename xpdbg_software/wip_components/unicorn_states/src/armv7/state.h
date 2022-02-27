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
