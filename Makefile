OBJ = capture/debug.o capture/decode.o capture/neti.o capture/netistats.o \
	capture/strlcpyu.o capture/util.o capture.o secvis.o gfx.o list.o \
	miscgl.o gui.o
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBS = -lpcap -lpthread -lglut -lGL -lGLU -lXmu -lXi -lXext -lX11 -lm -lqt-mt
	LIBPATH = -L/opt/X11/lib -L/opt/local/lib/qt3/lib
	INCPATH = -I/opt/local/include/qt3 -I/opt/X11/include
	CXXFLAGS = $(INCPATH) -Wall
else
	LIBS = -lpcap -lpthread -lglut -lGL -lGLU -lXmu -lXi -lXext -lX11 -lm -lqt
	LIBPATH = -L/usr/X11R6/lib/ -L/usr/qt/3/lib/
	INCPATH = -I/usr/qt/3/include -I/usr/qt/3/mkspecs/linux-g++
	CXXFLAGS = $(INCPATH)
endif

#.cc.o:
#	g++ -c $(CXXFLAGS) $(INCPATH) -o $@ $<

secvis: $(OBJ)
	g++ -g -o secvis $(OBJ) $(LIBPATH) $(LIBS) $(INCPATH)

clean:
	rm -f secvis *.o capture/*.o
