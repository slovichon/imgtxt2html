# $Id$

TARGET = imgtxt2html
CFLAGS = -I/usr/local/include
LIBS = -lgd -ljpeg -L/usr/local/lib

.c:
	cc -o ${TARGET} ${CFLAGS} ${LIBS} ${.IMPSRC}
	
all: ${TARGET}

clean:
	rm -f ${TARGET}
