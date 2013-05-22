// $Id: secvis.cc,v 1.7 2005/02/23 21:49:12 sven Exp $

#include <iostream>
//#include <stdio.h>
#include "capture/neti.h"
#include "gfx.h"
#include "capture.h"
#include "gui.h"

int dummy;
extern float playback_time;
extern long max_age;

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

//	while (1) {
		//std::cout << "max_age =" << std::endl;
		//std::cin >> max_age;
		//scanf("%ld", &max_age);
		//std::cout << "pkt_info_list:" << std::endl;
		//debug_print_pkt_info();
		//std::cout << playback_time << std::endl;
//		usleep(1000000);
//	}
	return 0;
}
