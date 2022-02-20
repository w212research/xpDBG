#include "xpDBG_window.h"
#include <gtkmm.h>
#include <cstdio>

int main(int	argc,
		 char  *argv[]) {
	/*
	 *  TODO: make this code look better, it looks like shit.
	 */
	int			fake_argc	= 1;
	char	  **fake_argv	= NULL;
	fake_argv				= (char**)calloc(sizeof(uintptr_t), 2);

	fake_argv[0] = argv[0];
	fake_argv[1] = NULL;

	auto app = Gtk::Application::create(fake_argc,
										fake_argv,
										"org.xpdbg.xpdbg");
	xpDBG_window window(argc, argv);

	return app->run(window);
}
