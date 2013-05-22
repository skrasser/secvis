// $Id: gfx.cc,v 1.27 2005/03/09 16:26:47 sven Exp $

#include <GL/glut.h>
#include <GL/gl.h>
#include <GL/glu.h>
#include <pthread.h>
#include <iostream>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "gfx.h"
#include "miscgl.h"
#include "capture.h"
#include "list.h"
#include "capture/neti.h"
#include "gui.h"
#include "secvis.h"

//#define BENCHMARK

pthread_t thread_gfx;

listnode *current_r, *prev_r, *first_r;
struct pkt_info *pinfo_r;
short rot;
extern LinkedList pkt_info_list;
char buffer[BUFSIZE];
int win_width = WIN_WIDTH, win_height = WIN_HEIGHT;
int zoom_y;
GLfloat ortho_top = 1.0, ortho_bottom = 0.0, persp_tx = 0.0, persp_ty = -0.35, persp_fov = 40.0;
struct timeval now;
int64_t timediff;
int64_t max_age = 20000000, max_age_sec;
float age_ratio;
extern pthread_mutex_t mutex_pkt_info_list;
bool middle_button = false, left_button = false, right_button = false;
int drag_x, drag_y;
struct pkt_info *data;
bool find_closest = false;
struct in_addr ipaddr;
unsigned short port = 0;
unsigned char mode = MODE_ORTHO;
bool display_throbber = true, display_grid = false;
extern struct timeval playback_time, ts_lastpkt;
extern bool playback_mode;
extern double playback_speed;
extern unsigned long buffer_count;
extern listnode **skiptable;

GLint viewport[4];
GLdouble modelview[16], projection[16];

#ifdef BENCHMARK
struct timeval benchmark_now, benchmark_start;
unsigned int framecount = 0;
#endif

void *begin_gfx(void*) {
	glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB);
	glutInitWindowSize(WIN_WIDTH, WIN_HEIGHT);
	glutInitWindowPosition(50, 50);
	glutCreateWindow("SecVis");

	glShadeModel(GL_FLAT);
	
	glClearColor(0.0, 0.0, 0.0, 0.0);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();

	glOrtho(-4.0, 4.0, 0.0, 1.0, -1.0, 1.0);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
	
	glutDisplayFunc(&display_func);
	glutIdleFunc(&idle_func);
	glutKeyboardFunc(&keyboard_func);
	glutReshapeFunc(&reshape_func);
	glutMouseFunc(&mouse_func);
	glutMotionFunc(&motion_func);
		
#ifdef BENCHMARK	
	gettimeofday(&benchmark_start, 0);
	gettimeofday(&benchmark_now, 0);
#endif

	max_age_sec = max_age / 1000000;
		
	make_font();
	glutMainLoop();
	return 0;
}

void draw_marker(GLfloat x, GLfloat y) {
	glPushMatrix();
	glColor3f(1.0, 0.0, 0.0);
	glTranslatef(x, y, 0.0);
	glScalef(8.0*10.0/(float)win_width, (ortho_top - ortho_bottom) * 10.0/(float)(win_height), 0.0);
	glBegin(GL_LINE_STRIP);
		glVertex2i(-1, 0);
		glVertex2i(0, -1);
		glVertex2i(1, 0);
		glVertex2i(0, 1);
		glVertex2i(-1, 0);
	glEnd();
	glPopMatrix();
}

void display_func() {
	unsigned long count = 0;
	float f;
	double ypos;
	u_int32_t ipdiff = MAXIP, lowipdiff = MAXIP;
	unsigned short portdiff = MAXPORT, lowportdiff = MAXPORT, closeport;
	struct in_addr closeip, ipaddr2;
	GLfloat v1, v2, v3;
	unsigned long count_displ = 0;

	long closest_pkt_distance = 999999999; // just a big value...
	struct pkt_info *closest_pkt = 0; // packet closest to mouse pointer
	
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
	
	if(display_grid) {
		glColor3f(0.20, 0.20, 0.20);
		glBegin(GL_LINES);
			for(f = -4.0; f <= 4.0; f += 0.5) {
				glVertex3f(f, 0.0, 0.0);
				glVertex3f(f, 1.0, 0.0);
			}
			for(f = 0.0; f <= 1.0; f += 0.05) {
				glVertex3f(-4.0, f, 0.0);
				glVertex3f(4.0, f, 0.0);
			}
		glEnd();
	}
	
	// render packet data
	
	if(playback_mode) {
		now = playback_time;
	} else {
		if(gettimeofday(&now, 0)) {
			std::cerr << "Error: gettimeofday()" << std::endl;
		}
	}
	
	if(playback_mode && skiptable) {
		int skipindex = (now.tv_sec - max_age_sec) / SKIPTABLE_DELTA;
		if(skipindex < 0)
			skipindex = 0;
		current_r = skiptable[skipindex];
	} else {
		current_r = first_r = pkt_info_list.get_first();
	}
	prev_r = 0;
	
	// Have to get matrixes for projection function
	if(mode == MODE_ORTHO && right_button)
		get_matrixes();
		
	while(current_r) {
		count++;
		pinfo_r = (struct pkt_info*)(current_r->data);
		
		timediff = (int64_t)(now.tv_sec - pinfo_r->timestamp.tv_sec) * 1000000 + (now.tv_usec - pinfo_r->timestamp.tv_usec);
		//std::cout << count << " --- " << timediff << std::endl;
		
		age_ratio = 1.0 - (float)timediff / max_age;
		if(playback_mode && timediff < 0) {
			//current_r = current_r->next;
			current_r = 0;
		} else if(timediff > max_age) {
			if(playback_mode) { // don't delete packet info in playback mode
				current_r = current_r->next;
			} else {
				pthread_mutex_lock(&mutex_pkt_info_list);
				if(current_r == first_r) {
					first_r = current_r = current_r->next;
					prev_r = 0;
					data = (struct pkt_info*)pkt_info_list.del_first();
				} else { // this shouldn't execute if all packets are in chronological order
					current_r = current_r->next;
					if(prev_r)
						data = (struct pkt_info*)pkt_info_list.del_next(prev_r);
				}
				pthread_mutex_unlock(&mutex_pkt_info_list);
				if(data) {
					if(data->payload)
						delete[] data->payload;
					free(data);
				}
			}
		} else {
			count_displ++;
			v1 = (float)pinfo_r->sip/MAXIP;
			v2 = (float)pinfo_r->dport/MAXPORT;
			
			if(port && right_button) {
				if(pinfo_r->sip > ipaddr.s_addr) {
					ipdiff = pinfo_r->sip - ipaddr.s_addr;
				} else {
					ipdiff = ipaddr.s_addr - pinfo_r->sip;
				}
				if(ipdiff < lowipdiff) {
					lowipdiff = ipdiff;
					closeip.s_addr = pinfo_r->sip;
				}
				if(pinfo_r->dport > port) {
					portdiff = pinfo_r->dport - port;
				} else {
					portdiff = port - pinfo_r->dport;
				}
				if(portdiff < lowportdiff) {
					lowportdiff = portdiff;
					closeport = pinfo_r -> dport;
				}
			}
			
			// Middle part
			switch(pinfo_r->proto) {
				case PKT_TCP:
					glColor3f(0.0, age_ratio, 0.0);
					break;
				case PKT_UDP:
					glColor3f(0.0, 0.0, age_ratio);
			}

			glBegin(GL_LINES);
				glVertex3f(-1.0, v1, 0.0);
				glVertex3f(1.0, v2, 0.0);
			glEnd();
			
			if (mode == MODE_PERSPECTIVE && right_button) {
				glColor3f(1.0, 0.0, 0.0);
				snprintf(buffer, BUFSIZE, "%d", pinfo_r->dport);
				draw_string(1.0, v2, buffer);
				
				ipaddr2.s_addr = htonl(pinfo_r->sip);
				draw_string(-1.0, v1, inet_ntoa(ipaddr2));				
			}
			
			prev_r = current_r;
			current_r = current_r->next;
			
			// Left and right part
			switch(pinfo_r->proto) {
				case PKT_TCP:
					glColor3f(0.0, 1.0, 0.0);
					break;
				case PKT_UDP:
					glColor3f(0.0, 0.0, 1.0);
			}
			
			if(mode == MODE_ORTHO && right_button) {
				GLdouble pkt_win_x, pkt_win_y;
				long distance; // square of distance between packet representation and mouse pointer
				if(drag_x < (win_width / 2)) {
					// mouse pointer is in the left half
					project_ortho(&pkt_win_x, &pkt_win_y, -4.0 + 3.0 * age_ratio, v1, 0.0);
				} else {
					project_ortho(&pkt_win_x, &pkt_win_y, 4.0 - 3.0 * age_ratio, v2, 0.0);
				}
				
				// apparently viewport and window coordinates are defined differently...
				pkt_win_y = win_height - pkt_win_y;
				
				distance = (long)((pkt_win_x - drag_x) * (pkt_win_x - drag_x) + (pkt_win_y - drag_y) * (pkt_win_y - drag_y));
				if(distance < closest_pkt_distance) {
					closest_pkt_distance = distance;
					closest_pkt = pinfo_r;
				//	std::cout << sqrt(distance) << " " << pkt_win_x << " " << pkt_win_y << " " << drag_x << " " << drag_y << std::endl;
				}
			//	project_ortho(&pkt_win_x, &pkt_win_y, -4.0, 0.0, 0.0);
			//	std::cout << "+++++++++++ " << pkt_win_x << "   " << pkt_win_y << std::endl;
			//	project_ortho(&pkt_win_x, &pkt_win_y, 4.0, 1.0, 0.0);
			//	std::cout << "+++++++++++ " << pkt_win_x << "   " << pkt_win_y << std::endl;
			}
			
			switch(mode) {
				case MODE_ORTHO:
					glBegin(GL_POINTS);
						glVertex3f(-4.0 + 3.0 * age_ratio, v1, 0.0);
						//glVertex3f(-4.0 + 3.0 * age_ratio, v1, 1.0);
						glVertex3f(4.0 - 3.0 * age_ratio, v2, 0.0);
						//glVertex3f(4.0 - 3.0 * age_ratio, v2, 1.0);
					glEnd();
					break;
				case MODE_PERSPECTIVE:
					glEnable(GL_DEPTH_TEST);
					v3 = (float)pinfo_r->len / MAXLEN;
					glBegin(GL_LINES);
						glVertex3f(-4.0 + 3.0 * age_ratio, v1, 0.0);
						glVertex3f(-4.0 + 3.0 * age_ratio, v1, v3);
						glVertex3f(4.0 - 3.0 * age_ratio, v2, 0.0);
						glVertex3f(4.0 - 3.0 * age_ratio, v2, v3);
					glEnd();
					glDisable(GL_DEPTH_TEST);
					break;
			}
		}
	}
	
	if(right_button) {
		switch(mode) {
			case MODE_ORTHO:
				glColor3f(1.0, 1.0, 1.0);
				ypos = unproject_ortho(drag_y);
				port = (unsigned short)floor(ypos * MAXPORT + 0.5);
				snprintf(buffer, BUFSIZE, "%d", port);
				draw_string(1.0, ypos, buffer);
				ipaddr.s_addr = htonl((unsigned long)floor(ypos * MAXIP + 0.5));
				draw_string(-2.0, ypos, inet_ntoa(ipaddr));
				ipaddr.s_addr = ntohl(ipaddr.s_addr); // leave in host order for ip distance calculation
				break;
			case MODE_PERSPECTIVE:
				break;
		}
	}
	
	
	// render informational stuff
	
	glColor3f(1.0, 1.0, 1.0);
	glBegin(GL_LINES);
		glVertex3f(-1.0, 0.0, 0.0);
		glVertex3f(-1.0, 1.0, 0.0);
		glVertex3f(1.0, 0.0, 0.0);
		glVertex3f(1.0, 1.0, 0.0);
	glEnd();
	
	glMatrixMode(GL_PROJECTION);
	glPushMatrix();
	glLoadIdentity();
	gluOrtho2D(0.0, 1.0, 0.0, 1.0);
	
	//     packet count
	glMatrixMode(GL_MODELVIEW);
	glPushMatrix();
	if(playback_mode) {
		float percentage = (100.0 * (float)now.tv_sec / (float)ts_lastpkt.tv_sec);
		snprintf(buffer, BUFSIZE, "Time range %lld sec, displaying %ld packets, %ld buffered, %ld itc, at %ld.%08d secs (%.0f%%), x%.1f", max_age_sec, count_displ, buffer_count, count, now.tv_sec, now.tv_usec, percentage, playback_speed);
	} else
		snprintf(buffer, BUFSIZE, "Time range %lld sec, displaying %ld packets", max_age_sec, count);
	draw_string(0.0, 0.0, buffer);
	
	//     close port/IP
/*	if(count && right_button) {
		closeip.s_addr = htonl(closeip.s_addr);
		snprintf(buffer, BUFSIZE, "Closest IP %s, Closest Port %d", inet_ntoa(closeip), closeport);
		draw_string(0.4, 0.0, buffer);
	}*/
	
	//     throbber
	if(display_throbber) {
		rot += 10;
		rot %= 360;

		glTranslatef(0.95, 0.05, 0.0);
		glScalef(0.01, 0.01, 0.0);
		glRotatef((GLfloat)rot, 0.0, 0.0, 1.0);
		glBegin(GL_LINES);
			glVertex3f(-1.0, 0.0, 0.0);
			glVertex3f(1.0, 0.0, 0.0);
		glEnd();
	}
	glPopMatrix();
	glMatrixMode(GL_PROJECTION);
	glPopMatrix();
	glMatrixMode(GL_MODELVIEW);
	
	if(closest_pkt) {
		// this pointer is set in ortho mode if the right mouse button is pressed
		// doing stuff twice here... the code needs some serious cleanup
		GLfloat pkt_x, pkt_y;
		int64_t timediff2 = (int64_t)(now.tv_sec - closest_pkt->timestamp.tv_sec) * 1000000 + (now.tv_usec - closest_pkt->timestamp.tv_usec);
		float age_ratio2 = 1.0 - (float)timediff2 / max_age;
				
		pkt_x = -4.0 + 3.0 * age_ratio2;
		pkt_y = (float)closest_pkt->sip/MAXIP;
		draw_marker(pkt_x, pkt_y);

		pkt_x = 4.0 - 3.0 * age_ratio2;
		pkt_y = (float)closest_pkt->dport/MAXPORT;
		draw_marker(pkt_x, pkt_y);
		
		textbox_pkt_info(closest_pkt);
		
		//std::cout << "------------------" << pkt_x << " " << pkt_y << std::endl;
	}
	
#ifdef BENCHMARK
	// This works at a one-second granularity, which should work fine
	// as long as the code runs at least in the order of 10 to 100 times 
	// per second
	
	gettimeofday(&benchmark_now, 0);
	//benchmark_now.tv_sec = now.tv_sec; // this only works in real-time mode but may be a bit faster
	
	framecount++;
	if(benchmark_now.tv_sec - benchmark_start.tv_sec >= 5) {
		float secs = benchmark_now.tv_sec - benchmark_start.tv_sec;
		benchmark_start.tv_sec = benchmark_now.tv_sec;
		float fps = framecount / secs;
		framecount = 0;
		std::cout << "packets " << count << " fps " << fps << std::endl;
	}
#endif
	
	glutSwapBuffers();
}

void do_zoom(float zoom_m) {
	float ypos;
	float ortho_top_old;
		
	ypos = unproject_ortho(zoom_y);
	ortho_top_old = ortho_top;
	
	ortho_top = zoom_m * (ortho_top - ypos) + ypos;
	ortho_bottom = ypos - (ortho_top - ypos) * (ypos - ortho_bottom) / (ortho_top_old - ypos);
	
	if(ortho_bottom < 0.0)
		ortho_bottom = 0.0;
	if(ortho_top > 1.0)
		ortho_top = 1.0;
			
	if(ortho_bottom > 1.0)
		ortho_bottom = 1.0;
	if(ortho_top < 0.0)
		ortho_top = 0.0;
		
	//std::cout << "zoom m" << zoom_m << " y " << zoom_y << " " << ypos << " " <<  ortho_bottom << " " << ortho_top << std::endl;
	
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(-4.0, 4.0, ortho_bottom, ortho_top, -1.0, 1.0);
	glMatrixMode(GL_MODELVIEW);
}

void idle_func() {
	glutPostRedisplay();
}

void keyboard_func(unsigned char key, int x, int y) {
	switch(key) {
		case 'q':
			// This still doesn't really work...
			std::cerr << "Quitting" << std::endl;
			exit(0);
			break;
		case 'o':
			ortho_bottom = 0.0;
			ortho_top = 1.0;
			switch(mode) {
				case MODE_ORTHO:
					glMatrixMode(GL_PROJECTION);
					glLoadIdentity();
					glOrtho(-4.0, 4.0, ortho_bottom, ortho_top, -1.0, 1.0);
					glMatrixMode(GL_MODELVIEW);
					glutPostRedisplay();
					break;
				case MODE_PERSPECTIVE:
					persp_tx = 0.0;
					persp_ty = -0.35;
					persp_fov = 40.0;
					set_persp_matrix();
					break;
			}
			break;
		case 'c':
			std::cout << "x " << x << " y " << y << std::endl;
			break;
		case 'g':
			display_grid = !display_grid;
			break;
		case 't':
			display_throbber = !display_throbber;
			break;
		case 'p':
			if(mode == MODE_ORTHO) {
				mode = MODE_PERSPECTIVE;
				set_persp_matrix();
			} else {
				mode = MODE_ORTHO;
				glMatrixMode(GL_PROJECTION);
				glLoadIdentity();
				glOrtho(-4.0, 4.0, ortho_bottom, ortho_top, -1.0, 1.0);
				glMatrixMode(GL_MODELVIEW);
				glutPostRedisplay();
			}
			break;
		case ']':
			if(playback_speed == 0.0)
				playback_speed = 1.0;
			else if(playback_speed > 0.0)
				playback_speed *= 2.0;
			else if(playback_speed < -1.0)
				playback_speed /= 2.0;
			else
				playback_speed = 0.0;
			break;
		case '[': 
			if(playback_speed == 0.0)
				playback_speed = -1.0;
			else if(playback_speed < 0.0)
				playback_speed *= 2.0;
			else if(playback_speed > 1.0)
				playback_speed /= 2.0;
			else
				playback_speed = 0.0;
			break;
		case '\\':
			playback_speed *= -1.0;
			break;
		case '\'':
			playback_speed = 0.0;
			break;
		case 'm':
			max_age *= 2;
			std::cout << "max_age = " << max_age << std::endl;
			max_age_sec = max_age / 1000000;
			break;
		case 'n':
			if(max_age > 1)
				max_age /= 2;
			std::cout << "max_age = " << max_age << std::endl;
			max_age_sec = max_age / 1000000;
			break;
		case 'b':
			max_age = 20000000;
			max_age_sec = max_age / 1000000;
			break;
		case '1':
			left_button = !left_button;
			break;
		case '2':
			middle_button = !middle_button;
			break;
		case '3':
			right_button = !right_button;
			break;
	}
}

void mouse_func(int button, int state, int x, int y) {
	//std::cout << "b " << button << " s " << state << " x " << x << " y " << y << std::endl;
	drag_x = x;
	drag_y = y;
	switch(button) {
		case GLUT_LEFT_BUTTON:
			left_button = state == GLUT_DOWN;
			zoom_y = y;
			break;
		
		case GLUT_MIDDLE_BUTTON:
			middle_button = state == GLUT_DOWN;
			break;
		
		case GLUT_RIGHT_BUTTON:
			right_button = state == GLUT_DOWN;
			break;
	}
}

void set_persp_matrix() {
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	gluPerspective(persp_fov, (GLdouble)WIN_WIDTH/WIN_HEIGHT, 1.0, 310.0);
	glTranslatef(0.0, 0.0, -5.0);
	glRotatef(-50.0, 1.0, 0.0, 0.0);
	glScalef(1.0, 5.0, 1.0);
	glTranslatef(persp_tx, persp_ty, 0.0);
	glMatrixMode(GL_MODELVIEW);
	glutPostRedisplay();
}

void motion_func(int x, int y) {
//	std::cout << "motion " << " x " << x << " y " << y << std::endl;
	switch(mode) {
		case MODE_ORTHO:
			if(left_button) {
				int delta_x = x - drag_x;
				float zoom_m;
				zoom_m = 1.0 - (float)delta_x / 100;
				do_zoom(zoom_m);
			}
			if(middle_button) {
				int delta_y = y - drag_y;
				float delta_p = ortho_top - ortho_bottom;
				float delta_m = delta_p * (float)delta_y / win_height;
				if(ortho_top + delta_m < 1.0 && ortho_bottom + delta_m > 0.0) {
					ortho_top += delta_m;
					ortho_bottom += delta_m;
					glMatrixMode(GL_PROJECTION);
					glLoadIdentity();
					glOrtho(-4.0, 4.0, ortho_bottom, ortho_top, -1.0, 1.0);
					glMatrixMode(GL_MODELVIEW);
				}
			}
			break;
		case MODE_PERSPECTIVE:
			if(left_button) {
				persp_fov += y - drag_y;
				if(persp_fov < 5.0) {
					persp_fov = 5.0;
				} else if(persp_fov > 100.0) {
					persp_fov = 100.0;
				}
				set_persp_matrix();
			}
			if(middle_button) {
				persp_tx += 2.0 * (float)(x - drag_x) / win_width;
				persp_ty += (float)(drag_y -y ) / win_height;
				std::cout << "motion " << " x " << persp_tx << " y " << persp_ty << std::endl;
				set_persp_matrix();
			}
			break;
	}
	drag_x = x;
	drag_y = y;
}

double unproject_ortho(int screen_y) {
	return ortho_bottom + (1.0 - (double)(screen_y + 1)/win_height) * (double)(ortho_top - ortho_bottom);
}

void get_matrixes() {
	glGetIntegerv(GL_VIEWPORT, viewport);
	glGetDoublev(GL_MODELVIEW_MATRIX, modelview);
	glGetDoublev(GL_PROJECTION_MATRIX, projection);
}

void project_ortho(GLdouble *winx, GLdouble *winy, GLdouble objx, GLdouble objy, GLdouble objz) {
	GLdouble winz; // dummy
	gluProject(objx, objy, objz, modelview, projection, viewport, winx, winy, &winz);
}

void reshape_func(int w, int h) {
	win_width = w;
	win_height = h;
	
	glViewport(0, 0, w, h);
//	glMatrixMode(GL_PROJECTION);
//	glLoadIdentity();
//	glOrtho(-4.0, 4.0, 0.0, 1.0, -1.0, 1.0);
//	glMatrixMode(GL_MODELVIEW);
	
	std::cout << "w " << w << " h " << h << std::endl;
}

void gfx_main(int &argc, char **argv) {
	glutInit(&argc,argv);
	
	if(pthread_create(&thread_gfx, NULL, &begin_gfx, NULL)) {
		std::cerr << "Could not spawn graphics thread." << std::endl;
		exit(0);
	}
}
