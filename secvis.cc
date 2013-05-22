// $Id: secvis.cc,v 1.7 2005/02/23 21:49:12 sven Exp $

#include <iostream>
#include "capture/neti.h"
#include "gfx.h"
#include "capture.h"
#include "gui.h"

void init() {
}

int main(int argc, char **argv) {
	init();
	gui_init(argc, argv);	
	
	gfx_main(argc, argv); // Initialize OpenGL and spawn render thread
	std::cerr << "Graphics initialized" << std::endl;
	
	neti_main(argc, argv); // Initialize neti code and spawn capture thread
	init_capture(); // Initialize capture glue code
	std::cerr << "Packet capturing initialized" << std::endl;

	gui_run();

	return 0;
}
