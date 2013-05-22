secvis was written by Sven Krasser in Spring 2005
and has been released under the GPL. http://www.gnu.org/licenses/gpl.html

It is a quick prototype, but we believed that the
value of releasing it outweighed the, possibly infinite,
delay required for us to clean up the code.  

We would like to thank Robby Simpson of the NETI@Home project
for his help.  We also want to mention that some of the
code has been derived from both the NETI@Home project
and from Snort.  Our thanks go out to both projects.

Some usage notes follow.

Thanks,
Greg Conti and Sven Krasser



******** secvis usage notes ****************

A makefile is included

Run the program as root for pcap, for example with 'sudo.'

Real-time mode: For example:
sudo ./secvis -i eth0

Forensic mode:
./secvis -r pcap-file


Filter in both modes:
Add option -f, e.g.: -f "not host 192.168.100.100"
Filter strings are described in "man tcpdump."

Running:

Mouse: left button: zoom (2D: move left/right, 3D: move up/down),
middle button: panning, right button: show more information

Keyboard:
Speed control for playback: '[' and ']'
Time window: n and m
Grid: g
Throbber: t
Change 2D/3D: p
Revert to standard view: o


1, 2, and 3 emulate the mouse buttons. Press 1, 2 or 3 Then click 
with any button into the window. It will then pick up the new mouse coordinates. 
Pressing the numbers only toggles the mouse button state, so that you 
still need to click to make the program fetch coordinates.


Pressing q should end the program, buy the cleanup code is messy.
This here should always do the job: sudo killall -9 secvis.

The right button should mark the nearest packet, the middle one is for 
panning. If you don't have a middle button, you can use the Emulate 3 
Button Mouse option in X11. 


