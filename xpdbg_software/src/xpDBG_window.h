#ifndef XPDBG_WINDOW_H
#define XPDBG_WINDOW_H

#include <gtkmm.h>

class xpDBG_window : public Gtk::Window {
public:
	xpDBG_window(int   argc,
				 char* argv[]);
	virtual ~xpDBG_window();
protected:
	Gtk::Button step_button;
	Gtk::ScrolledWindow sw;
	Gtk::TextView reg_view;
	Gtk::Box button_box;
	Gtk::Grid our_grid;
	Gtk::Box emu_box;
	Gtk::Box our_box;
	void step_clicked();
};

#endif
