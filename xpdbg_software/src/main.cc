#include "xpDBG_window.h"
#include <gtkmm.h>
#include <cstdio>

int main(int	argc,
		 char  *argv[]) {
	auto app = Gtk::Application::create(argc,
										argv,
										"org.xpdbg.xpdbg");
	xpDBG_window window;

	return app->run(window);
}
