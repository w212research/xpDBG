#ifndef XPDBG_WINDOW_H
#define XPDBG_WINDOW_H

#include <gtkmm.h>

class xpDBG_window : public Gtk::Window {
public:
	xpDBG_window(int		argc,
				 char	   *argv[]); 
	virtual ~xpDBG_window();
};

#endif
