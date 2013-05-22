#include <GL/glut.h>
#include <string.h>
#include "miscgl.h"

GLuint font_offset;

/* code from CS6480 */
void make_font(void)	
{
    GLuint i;
    font_offset = glGenLists (128);
    for (i = 0; i < 128; i++) {
       glNewList(font_offset + i, GL_COMPILE);
       glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, i);
       glEndList();
    }
}

/* code from CS6480 */
void draw_string(GLfloat x, GLfloat y, char *s)	
{
    glRasterPos2f(x, y);
    glListBase(font_offset);
    glCallLists(strlen(s), GL_BYTE, s);
}
