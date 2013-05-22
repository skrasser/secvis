// $Id: gfx.h,v 1.11 2005/03/09 16:26:47 sven Exp $

#ifndef GFX_H
#define GFX_H

#include <GL/gl.h>

#define WIN_WIDTH 800
#define WIN_HEIGHT 600

#define MAXPORT 0xffff
#define MAXIP 0xffffffff
#define MAXLEN 1500 // assuming Ethernet here

#define MODE_ORTHO 1
#define MODE_PERSPECTIVE 2

void *begin_gfx(void*);
void display_func();
void idle_func();
void keyboard_func(unsigned char key, int x, int y);
void reshape_func(int w, int h);
void mouse_func(int button, int state, int x, int y);
void motion_func(int x, int y);
double unproject_ortho(int screen_y);
void get_matrixes();
void project_ortho(GLdouble *winx, GLdouble *winy, GLdouble objx, GLdouble objy, GLdouble objz);
void set_persp_matrix();
void gfx_main(int&, char**);

#endif
