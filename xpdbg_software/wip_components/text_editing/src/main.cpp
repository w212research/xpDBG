#include "xpDBG_window.h"
#include "logging.h"
#include <gtkmm.h>
#include <cstdio>

int main(int	argc,
		 char  *argv[]) {
	/*
	 *  TODO: make this code look better, it looks like shit.
	 *
	 *  This code creates a fake argc and argv that only contains the name of
	 *  the binary, otherwise GTK gets mad at the moment, complaining that we
	 *  don't take files as arguments or something.
	 *
	 *  spv@jkek420:/.../xpdbg/xpdbg_software$ bin/main res/test1.bin
	 *
	 *  (main:13170): GLib-GIO-CRITICAL **: 14:22:18.291: This application can not open files.
	 *  spv@jkek420:/.../xpdbg/xpdbg_software$
	 */
	int			fake_argc	= 1;
	char	  **fake_argv	= NULL;
	fake_argv				= (char**)calloc(sizeof(uintptr_t), 2);

	/*
	 *  populate the array
	 */
	fake_argv[0] = argv[0];
	fake_argv[1] = NULL;

	xpdbg_set_log_level(LOG_VERBOSE);
	xpdbg_log(LOG_INFO, "xpDBG Loaded.");

	/*
	 *  create the app
	 */
	xpdbg_log(LOG_INFO, "Creating GTK application...");
	auto app = Gtk::Application::create(fake_argc,
										fake_argv,
										"org.xpdbg.xpdbg");

	/*
	 *  create the window object
	 */
	xpdbg_log(LOG_INFO, "Creating xpDBG_window...");
	xpDBG_window window(argc,
						argv);


	/*
	 *  run it
	 */
	xpdbg_log(LOG_INFO, "Running xpDBG_window...");
	return app->run(window);
}
