#ifndef STATE_H
#define STATE_H

struct mem_change_t_struct {
	uint64_t where;
	uint64_t size;
	void* what;
};

struct armv7_reg_state_t_struct {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	uint32_t r13;
	uint32_t r14;
	uint32_t r15;
};

typedef struct mem_change_t_struct mem_change_t;
typedef struct armv7_reg_state_t_struct armv7_reg_state_t;

struct armv7_state_change_t_struct {
	armv7_reg_state_t reg_state;
	mem_change_t mem_change;
};

typedef struct armv7_state_change_t_struct armv7_state_change_t;

#endif
