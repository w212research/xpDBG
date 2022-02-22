#include <capstone/capstone.h>
#include "xpDBG_window.h"
#include "logging.h"
#include <gtkmm.h>

using namespace std;

#define ADDRESS_FORMAT "0x%08llx"
#define DISASSEMBLY_STR ADDRESS_FORMAT ":\t%s\t%s"

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

xpDBG_window::xpDBG_window(int		argc,
						   char	   *argv[]) {
	char*    filename;
	csh      handle;
	size_t   count;
	cs_insn* insn;
	uint8_t* buf;
	size_t   len;
	int      i;

	xpdbg_log(LOG_INFO, "Landed in xpDBG_window.");
	xpdbg_log(LOG_INFO, "Asking for file for disassembly...");
	Gtk::FileChooserDialog dialog("Please choose a file for disassembly.",
								  Gtk::FILE_CHOOSER_ACTION_OPEN);
	dialog.set_transient_for(*this);

	dialog.add_button("_Cancel",	Gtk::RESPONSE_CANCEL);
	dialog.add_button("_Open",		Gtk::RESPONSE_OK);

	int result = dialog.run();
	switch (result) {
		case (Gtk::RESPONSE_OK): {
			/*
			 *  strdup because otherwise it breaks or something
			 *  god, i love memory management
			 */

			xpdbg_log(LOG_INFO, "User chose to open file.");
			filename = strdup(dialog.get_filename().c_str());
			xpdbg_log(LOG_INFO, "Filename: %s", filename);
			break;
		} case (Gtk::RESPONSE_CANCEL): {
			xpdbg_log(LOG_INFO, "User cancelled file opening.");
			filename = NULL;
			break;
		} default: {
			xpdbg_log(LOG_ERROR, "Something went wrong.");
			return;
			break;
		}
	}

	if (filename == NULL) {
		xpdbg_log(LOG_INFO, "Using built-in test code.");
		buf = test_arm_thumb_code;
		len = sizeof(test_arm_thumb_code);
	} else {
		xpdbg_log(LOG_INFO, "Opening %s...",
				  filename);
		FILE   *fp	= fopen(filename, "rb");

		fseek(fp, 0, SEEK_END);
		len	= ftell(fp);
		rewind(fp);

		xpdbg_log(LOG_INFO, "File is %d bytes (0x%x in hex) long.",
				  len,
				  len);

		/*
		 *  i'm aware that sizeof(uint8_t); should be 1 on any normal system,
		 *  and now that i think about it, it always should be (i think):
		 *  a uint8_t i think is defined as at least 8 bits, so even on systems
		 *  where CHAR_BIT != 8, it has to be at least 8, so sizeof(uint8_t)
		 *  should always be 1. i think. eh whatever security
		 */

		xpdbg_log(LOG_VERBOSE, "Allocating memory...");

		buf	= (uint8_t*)calloc(len,
							   len / sizeof(uint8_t));
		fread(buf,
			  sizeof(uint8_t),
			  len / sizeof(uint8_t),
			  fp);
		fclose(fp);
	}

	set_title("Disassembly");
	set_default_size(640,
					 480);

	/*
	 *  create a TextView for the disassembly, as well as a TextBuffer for
	 *  containing the text
	 */
	xpdbg_log(LOG_VERBOSE, "Creating GTK TextView and TextBuffer...");
	auto* our_text_view   = new Gtk::TextView();
	auto  our_text_buffer = Gtk::TextBuffer::create();

	/*
	 *  monospace looks better :P
	 *  also we don't want it to be editable
	 */
	xpdbg_log(LOG_VERBOSE, "Setting TextView properties...");
	our_text_view->set_monospace(true);
	our_text_view->set_editable(false);
	our_text_view->set_buffer(our_text_buffer);

	/*
	 *  open capstone handle
	 *  CS_MODE_THUMB as this is thumb code
	 */
	xpdbg_log(LOG_VERBOSE, "Opening Capstone handle.");
	cs_open(CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB),
			&handle);

	/*
	 *  disassemble it
	 */
	xpdbg_log(LOG_INFO, "Disassembling code...");
	count = cs_disasm(handle,
					  buf,
					  len,
					  0x1000,
					  0,
					  &insn);


	/*
	 *  initialize with empty string, otherwise it'll start with "(null)"
	 */
	xpdbg_log(LOG_INFO, "Formatting disassembly...");
	char* disassembly_text = NULL;

	asprintf(&disassembly_text,
			 "");

	/*
	 *  format it
	 */
	if (count > 0) {
		for (i = 0; i < count; i++) {
			asprintf(&disassembly_text,
					 "%s" DISASSEMBLY_STR "\n",
					 disassembly_text,
					 (unsigned long long)insn[i].address,
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
	xpdbg_log(LOG_VERBOSE, "Closing Capstone handle...");
	cs_close(&handle);

	/*
	 *  set the actual thing
	 */
	our_text_buffer->set_text(disassembly_text);

	/*
	 *  add text view to scrolledwindow and init scrolledwindow
	 */
	xpdbg_log(LOG_VERBOSE, "Initializing ScrolledWindow.");

	sw.set_policy(Gtk::POLICY_ALWAYS, Gtk::POLICY_ALWAYS);
	sw.set_border_width(10);

	xpdbg_log(LOG_VERBOSE, "Adding TextView.");
	sw.add(*our_text_view);
	sw.show_all_children();

	xpdbg_log(LOG_VERBOSE, "Adding ScrolledWinow...");
	add(sw);

	xpdbg_log(LOG_VERBOSE, "Showing...");
	show_all_children();
}

xpDBG_window::~xpDBG_window(void) {
	/*
	 *  empty function
	 */
}
