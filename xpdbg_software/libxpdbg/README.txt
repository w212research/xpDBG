                _ _
__  ___ __   __| | |__   __ _
\ \/ / '_ \ / _` | '_ \ / _` |
 >  <| |_) | (_| | |_) | (_| |
/_/\_\ .__/ \__,_|_.__/ \__, |
     |_|                |___/

libxpdbg

libxpdbg is meant to be a general-purpose library / API for controlling,
accessing, and generally manipulating emulated or real-silicon machines; and
managing reverse engineering, analysis, and general software research tasks in
a single, contained library.

Examples of targeted functionality include:
	- controlling/managing emulated machines, say for debugging purposes
	- providing an interface between custom software packages and other software
      that intends to provide general purpose machine support, à la xpDBG. [1]
	- disassembling machine code
	- decompiling machine code
	- assembling, compiling code
	- and more