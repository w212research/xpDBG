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
