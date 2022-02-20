#include <capstone/capstone.h>
#include "xpDBG_window.h"
#include <gtkmm.h>

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

xpDBG_window::xpDBG_window(int		argc,
						   char	   *argv[]) {
	cs_insn		   *insn;
	uint8_t		   *buf;
	size_t			count;
	csh				handle;
	int				i;

	set_title("Disassembly");
	set_default_size(200,
					 200);

	/*
	 *  create a TextView for the disassembly, as well as a TextBuffer for
	 *  containing the text
	 */
	auto   *our_text_view	= new Gtk::TextView();
	auto	our_text_buffer	= Gtk::TextBuffer::create();

	/*
	 *  monospace looks better :P
	 *  also we don't want it to be editable
	 */
	our_text_view->set_monospace(true);
	our_text_view->set_editable(false);
	our_text_view->set_buffer(our_text_buffer);
	size_t	len	= 0;

	/*
	 *  if the args are
	 *  ./main
	 *
	 *  just use the test code
	 *  otherwise, take the first arg (./main {whatever}), and open it for
	 *  disassembly.
	 */
	if (argc < 2) {
		buf = test_arm_thumb_code;
		len = sizeof(test_arm_thumb_code);
	} else {
		FILE   *fp	= fopen(argv[1], "rb");

		fseek(fp, 0, SEEK_END);
		len	= ftell(fp);
		rewind(fp);

		/*
		 *  i'm aware that sizeof(uint8_t); should be 1 on any normal system,
		 *  and now that i think about it, it always should be (i think):
		 *  a uint8_t i think is defined as at least 8 bits, so even on systems
		 *  where CHAR_BIT != 8, it has to be at least 8, so sizeof(uint8_t)
		 *  should always be 1. i think. eh whatever security
		 */
		buf	= (uint8_t*)calloc(len, len / sizeof(uint8_t));
		fread(buf, sizeof(uint8_t), len / sizeof(uint8_t), fp);
		fclose(fp);
	}

	/*
	 *  open capstone handle
	 *  CS_MODE_THUMB as this is thumb code
	 */
	cs_open(CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB),
			&handle);

	/*
	 *  disassemble it
	 */
	count = cs_disasm(handle,
					  buf,
					  len,
					  0x1000,
					  0,
					  &insn);

	/*
	 *  initialize with empty string, otherwise it'll start with "(null)"
	 */
	char   *disassembly_text	= (char*)"";

	/*
	 *  format it
	 */
	if (count > 0) {
		for (i = 0; i < count; i++) {
			asprintf(&disassembly_text, "%s0x%016lx:\t%s\t\t%s\n",
					 disassembly_text,
					 insn[i].address,
					 insn[i].mnemonic,
					 insn[i].op_str);
		}

		/*
		 *  no memory leaks here, sir
		 */
		cs_free(insn,
				count);
	}

	/*
	 *  good little programmers, we are
	 */
	cs_close(&handle);

	/*
	 *  set the actual thing
	 */
	our_text_buffer->set_text(disassembly_text);

	add(*our_text_view);

	show_all_children();
}

xpDBG_window::~xpDBG_window(void) {
	/*
	 *  empty function
	 */
}
