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

#ifndef XPDBG_WINDOW_H
#define XPDBG_WINDOW_H

#include <gtkmm.h>

class xpDBG_window : public Gtk::Window {
	public:
		xpDBG_window(int   argc,
					 char* argv[]);
		virtual ~xpDBG_window();
	protected:
		Gtk::ScrolledWindow           sw;
		Gtk::TextView*                our_text_view;
		Glib::RefPtr<Gtk::TextBuffer> our_text_buffer;
};

#endif
