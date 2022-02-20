#include <capstone/capstone.h>
#include <gtkmm.h>
#include <cstdio>

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

class xpDBG_window : public Gtk::Window {
public:
	xpDBG_window();
	virtual ~xpDBG_window();
};

xpDBG_window::xpDBG_window(void) {
	cs_insn		   *insn;
	size_t			count;
	csh				handle;
	int				i;

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
					  test_arm_thumb_code,
					  sizeof(test_arm_thumb_code),
					  0x1000,
					  0,
					  &insn);

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
		 * no memory leaks here, sir
		 */
		cs_free(insn,
				count);
	}

	/*
	 *  good little programmers, we are
	 */
	cs_close(&handle);

	set_title("Disassembly");
	set_default_size(200,
					 200);

	Gtk::TextView				   *our_text_view	=	new	Gtk::TextView();
	Glib::RefPtr<Gtk::TextBuffer>	our_text_buffer	=	Gtk::TextBuffer::create();
	our_text_buffer->set_text(disassembly_text);
	our_text_view->set_buffer(our_text_buffer);

	add(*our_text_view);

	show_all_children();
}

xpDBG_window::~xpDBG_window(void) {
	/*
	 *  empty function
	 */
}

int main(int	argc,
		 char  *argv[]) {
	auto			app		=	Gtk::Application::create(argc,
														 argv,
														 "org.xpdbg.xpdbg");
	xpDBG_window	window;

	return app->run(window);
}
