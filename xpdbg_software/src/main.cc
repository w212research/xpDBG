#include <capstone/capstone.h>
#include <gtk/gtk.h>
#include <cstdio>

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

void activate(GtkApplication   *app,
			  gpointer			user_data) {
	GtkWidget	   *window;
	GtkWidget	   *view;
	cs_insn		   *insn;
	size_t			count;
	csh				handle;
	int				i;

	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window),
						 "Disassembly");
	gtk_window_set_default_size(GTK_WINDOW(window),
								200,
								200);
	view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view),
							   FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view),
									 TRUE);


	/*
	 *  open capstone handle
	 *  CS_MODE_THUMB as this is thumb code
	 */
	cs_open(CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB),
			&handle);

	/*
	 *  disassemble it
	 */
	count = cs_disasm(handle,
					  test_arm_thumb_code,
					  sizeof(test_arm_thumb_code),
					  0x1000,
					  0,
					  &insn);

	char   *disassembly_text	= (char*)"";

	/*
	 *  print it
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
		 * no memory leaks here, sir
		 */
		cs_free(insn,
				count);
	}

	/*
	 *  good little programmers, we are
	 */
	cs_close(&handle);

	GtkTextBuffer  *buffer;
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
	gtk_text_buffer_set_text(buffer,
							 disassembly_text,
							 strlen(disassembly_text));
	
	gtk_container_add(GTK_CONTAINER(window),
					  GTK_WIDGET(view));

	gtk_widget_show_all(GTK_WIDGET(window));
}

int main(int	argc,
		 char  *argv[]) {
	GtkApplication *app;

	app = gtk_application_new("org.xpdbg.xpdbg",
						G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app,
					 "activate",
				 	 G_CALLBACK(activate),
				 	 NULL);
	g_application_run(G_APPLICATION(app),
					  argc,
				  	  argv);
	g_object_unref(app);

	return 0;
}
