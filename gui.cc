#include <qapplication.h> 
#include <qtextview.h>
#include <qlabel.h>
#include <qfont.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#include "secvis.h"
#include "capture.h"



QApplication *a;
//QTextView *textBox;
QLabel *textBox;

QString to_hex(unsigned char c)
{
	QString theString;
	unsigned char firstHex;
	unsigned char secHex;

	firstHex = (c>>4)%16;
	if(firstHex < 10)
	{
		firstHex += '0';
	}
	else
	{
		firstHex += 'A' - 10;
	}

	secHex = c%16;
	if(secHex < 10)
	{
		secHex += '0';
	}
	else
	{
		secHex += 'A' - 10;
	}

	theString.append(firstHex);
	theString.append(secHex);

	return theString;
}

char to_ascii(char c)
{
	if(c >= ' ' && c <= '~')
		return c;
	else
		return '.';
}

QString bytes_to_hexascii(char *text, int size)
{
	QString output;
	int i = 0;
	int j = 0;
	int evenSize = 0; /* stores even size as multiple of row_width */

	/* change this to adjust row_width
	 * row_width in terms of ascii char.  width will be
	 * row_width + 2*row_width for hex part
	 */
	int row_width = 16;

	/* change this to change spacing of hex digits
	 * note, that we divide this number by two below
	 * because each character counts as two hex digits.
	 * make this number even.
	 */
	int hex_space = 4;  

	/* change this to change spacing of ascii chars
	 */
	int ascii_space = 8;  


	hex_space = hex_space/2;

	evenSize = size/row_width*row_width;
	if(evenSize < size) evenSize += row_width;

	for(i = 0; i <= evenSize; i++)
	{
		/* ascii stuff, new line, spacing */
		if(i % row_width == 0 && i != 0)
		{
			/* do ascii part for this row */
			output.append("   ");
			for(j = i - row_width; j < i && j < size; j++)
			{
				if((j % row_width) % ascii_space == 0 && j % row_width != 0)
				{
					output.append(' ');
				}
				output.append(to_ascii(text[j]));
			}
			output.append('\n');
		}
		else if(i >= size && i % hex_space == 0 && i % row_width != 0)
		{
			/* last row, special case, fake the hex space */
			output.append(' ');
		}
		else if((i % row_width) % hex_space == 0 && i % row_width != 0)
		{
			/* put a space for hex */
			output.append(' ');
		}

		/* process new character or fake one */
		if(i < size)
		{
			/* more characters to process */ 
			output.append(to_hex(text[i]));

		}
		else
		{
			/* fake a character */
			output.append(' ');
			output.append(' ');
		}

	}

	return output;
}



void textbox_pkt_info(struct pkt_info *pinfo) {
	struct in_addr ipaddr;
	QString string;
	
	switch(pinfo->proto) {
		case PKT_TCP:
			string.append("TCP");
			break;
		case PKT_UDP:
			string.append("UDP");
			break;
		default:
			string.append("Unknown");
	}
	string.append(" ");
	
	ipaddr.s_addr = htonl(pinfo->sip);
	string.append(inet_ntoa(ipaddr));
	string = string.append(":%1").arg(pinfo->sport);

	string.append(" -> ");

	ipaddr.s_addr = htonl(pinfo->dip);
	string.append(inet_ntoa(ipaddr));
	string = string.append(":%1").arg(pinfo->dport);	
	
	string.append("\n\n");
	
	if(pinfo->payload)
		string.append(bytes_to_hexascii(pinfo->payload, pinfo->payload_len));
	
	//std::cout << string.latin1() << std::endl;
	//textBox->clear();
	
	textBox->setText(string);
}

void gui_init( int argc, char **argv ) 
{ 
	a = new QApplication( argc, argv );
	
	textBox = new QLabel(0);//new QTextView(0, 0);
	
	textBox->setFont(QFont("Courier", 12));
	textBox->setTextFormat(Qt::PlainText);
	textBox->resize(600, 140);
	textBox->setAlignment(Qt::AlignTop | Qt::AlignLeft);
	textBox->setCaption("SecVis Packet Information Output Window");
	textBox->setText("SecVis Packet Information Output Window");
	
	a->setMainWidget(textBox); 
	textBox->show();
}

int gui_run() {
	return a->exec();
}
