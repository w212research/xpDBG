#include <capstone/capstone.h>
#include "xpDBG_window.h"
#include "logging.h"
#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

void on_app_activate(GApplication  *app,
					 gpointer		data) {
	cs_insn*	insn;
	uint8_t*	buf;
	size_t		count;
	size_t		len;
	char*		filename;
	csh			handle;
	int			i;

	xpdbg_log(LOG_INFO, "Landed in xpDBG_window.");
	GtkWidget*		window		= gtk_application_window_new(GTK_APPLICATION(app));
	GtkWidget*		text_view	= gtk_text_view_new();
	GtkTextBuffer*	text_buffer	= gtk_text_buffer_new(NULL);

	gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_view), true);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), false);

	GtkFileChooserAction	action = GTK_FILE_CHOOSER_ACTION_OPEN;
	GtkWidget*				dialog;
	gint					res;

	xpdbg_log(LOG_INFO, "Asking for file for disassembly...");
	dialog = gtk_file_chooser_dialog_new("Please choose a file for disassembly.",
										 GTK_WINDOW(window),
										 action,
										 "_Cancel",
										 GTK_RESPONSE_CANCEL,
										 "_Open",
										 GTK_RESPONSE_OK,
										 NULL);
	res = gtk_dialog_run(GTK_DIALOG(dialog));
	if (res == GTK_RESPONSE_OK) {
		xpdbg_log(LOG_INFO, "User chose to open file.");
    	GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
    	filename = strdup(gtk_file_chooser_get_filename(chooser));
		xpdbg_log(LOG_INFO, "Filename: %s", filename);
	} else if (res == GTK_RESPONSE_CANCEL) {
		xpdbg_log(LOG_INFO, "User cancelled file opening, using default ARM code.");
		filename = NULL;
	} else {
		xpdbg_log(LOG_ERROR, "Something went wrong.");
	}

	gtk_widget_destroy(dialog);

	if (filename == NULL) {
		xpdbg_log(LOG_INFO, "Using built-in test code.");
		buf = test_arm_thumb_code;
		len = sizeof(test_arm_thumb_code);
	} else {
		xpdbg_log(LOG_INFO, "Opening %s...", filename);
		FILE   *fp	= fopen(filename, "rb");

		fseek(fp, 0, SEEK_END);
		len	= ftell(fp);
		rewind(fp);

		xpdbg_log(LOG_INFO, "File is %d bytes (0x%x in hex) long.", len, len);

		/*
		 *  i'm aware that sizeof(uint8_t); should be 1 on any normal system,
		 *  and now that i think about it, it always should be (i think):
		 *  a uint8_t i think is defined as at least 8 bits, so even on systems
		 *  where CHAR_BIT != 8, it has to be at least 8, so sizeof(uint8_t)
		 *  should always be 1. i think. eh whatever security
		 */

		xpdbg_log(LOG_VERBOSE, "Allocating memory...");

		buf	= (uint8_t*)calloc(len, len / sizeof(uint8_t));
		fread(buf, sizeof(uint8_t), len / sizeof(uint8_t), fp);
		fclose(fp);
	}

	gtk_window_set_title(GTK_WINDOW(window), "Disassembly");

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
	xpdbg_log(LOG_VERBOSE, "Closing Capstone handle...");
	cs_close(&handle);

	gtk_text_buffer_set_text(text_buffer, disassembly_text, -1);
	gtk_text_view_set_buffer(GTK_TEXT_VIEW(text_view), text_buffer);
	gtk_container_add(GTK_CONTAINER(window), text_view);
	gtk_widget_show_all(GTK_WIDGET(window));
}
