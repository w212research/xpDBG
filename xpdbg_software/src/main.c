#include "xpDBG_window.h"
#include <gtk/gtk.h>
#include "logging.h"
#include <stdio.h>

int main(int	argc,
		 char  *argv[]) {
	xpdbg_log(LOG_INFO, "xpDBG Loaded.");
	xpdbg_log(LOG_INFO, "Creating GTK application...");
	GtkApplication *app = gtk_application_new("org.xpdb.xpdbg",
											  G_APPLICATION_FLAGS_NONE);

	xpdbg_log(LOG_INFO, "Connecting GTK Signal...");
	g_signal_connect(app, "activate", G_CALLBACK(on_app_activate), NULL);

	xpdbg_log(LOG_INFO, "Running application...");
	int status = g_application_run(G_APPLICATION(app), argc, argv);

	xpdbg_log(LOG_INFO, "Cleaning up...");
	g_object_unref(app);
	return status;
}
