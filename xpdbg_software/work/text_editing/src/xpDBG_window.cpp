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

#include "xpDBG_window.h"
#include "logging.h"
#include <gtkmm.h>

using namespace std;

#define BORDER_WIDTH 10

xpDBG_window::xpDBG_window(int   argc,
						   char* argv[]) {
	char*    filename;
	size_t   count;
	uint8_t* buf;
	size_t   len;
	int      i;

	xpdbg_log(LOG_INFO, "Landed in xpDBG_window.");
	xpdbg_log(LOG_INFO, "Asking for file to edit...");
	Gtk::FileChooserDialog dialog("Please choose a file to edit.",
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
		xpdbg_log(LOG_INFO, "Using empty file.");
		filename = strdup("new file");
		len = 1;
		buf = (uint8_t*)calloc(len,
							   len / sizeof(uint8_t));
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

	set_title(filename);
	set_default_size(640,
					 480);

	/*
	 *  create a TextView for the text view, as well as a TextBuffer for
	 *  containing the text
	 */
	xpdbg_log(LOG_VERBOSE, "Creating GTK TextView and TextBuffer...");
	our_text_view   = new Gtk::TextView();
	our_text_buffer = Gtk::TextBuffer::create();

	/*
	 *  monospace looks better :P
	 *  also we want it to be editable
	 */
	xpdbg_log(LOG_VERBOSE, "Setting TextView properties...");
	our_text_view->set_monospace(true);
	our_text_view->set_editable(true);
	our_text_view->set_buffer(our_text_buffer);

	/*
	 *  set the actual thing
	 */
	our_text_buffer->set_text((char*)buf);

	/*
	 *  add text view to scrolledwindow and init scrolledwindow
	 */
	xpdbg_log(LOG_VERBOSE, "Initializing ScrolledWindow.");

	sw.set_policy(Gtk::POLICY_ALWAYS, Gtk::POLICY_ALWAYS);
	sw.set_border_width(BORDER_WIDTH);

	xpdbg_log(LOG_VERBOSE, "Adding TextView.");
	sw.add(*our_text_view);
	sw.show_all_children();

	xpdbg_log(LOG_VERBOSE, "Adding ScrolledWinow...");
	add(sw);

	xpdbg_log(LOG_VERBOSE, "Showing...");
	show_all_children();
}

xpDBG_window::~xpDBG_window(void) {
	printf("%s\n", our_text_buffer->get_text().c_str());
}
