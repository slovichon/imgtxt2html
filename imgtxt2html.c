/* $Id$ */

#include <stdio.h>
#include <stdarg.h>
#include <gd.h>
#include <sys/types.h>

#define TRUE  1
#define FALSE 0

typedef gdImagePtr (*INIT_FUNC)(FILE *);

void die(char *fmt, ...);
void usage();

struct ext_map {
	char *ext;
	INIT_FUNC init;
} map[] = {
	{ ".jpg",  gdImageCreateFromJpeg },
	{ ".jpeg", gdImageCreateFromJpeg },
	{ ".png",  gdImageCreateFromPng  },
	{ NULL,    NULL },
};

int main(int argc, char *argv[])
{
	gdImagePtr img;
	FILE *img_fp, *text_fp, *html_fp;
	char * img_file, *text_file, *html_file;
	int width, height, prev_pixel,
	    pixel, x, y, ch;
	INIT_FUNC img_init;
	struct ext_map *iter;

	/* Check arguments */
	if (argc != 3)
		usage();

	img_file  = argv[1];
	text_file = argv[2];

	/* Determine file type */
	img_init = NULL;
	for (iter = map; iter->ext != NULL; iter++) {
		if (strcasecmp(img_file + strlen(img_file) - strlen(iter->ext), iter->ext) == 0) {
			img_init = iter->init;
			break;
		}
	}

	if (img_init == NULL)
		die("Unknown filetype");

	/* Gather image data */
	img_fp = fopen(img_file, "rb");
	if (img_fp == NULL)
		die("Cannot open image file");
	img = (*img_init)(img_fp);
	fclose(img_fp);

	if (img == NULL)
		die("Malformed image file");

	width	= gdImageSX(img);
	height	= gdImageSY(img);

	/* Start gathering text data */
	text_fp = fopen(text_file, "r");
	if (text_fp == NULL)
		die("Cannot open text file");

	/*
	 * Loop from top left to the bottom right.
	 * After we see a pixel, save the color and
	 * compare the next pixel against this color
	 * to reduce HTML output.
	 */
	for (y = 1; y <= height; y++)
	{
		for (x = 1; x <= width; x++)
		{
			pixel = gdImageGetPixel(img, x, y);
			ch = fgetc(text_fp);

			if (prev_pixel &&
			    img->red[prev_pixel]   == img->red[pixel]   &&
			    img->green[prev_pixel] == img->green[pixel] &&
			    img->blue[prev_pixel]  == img->blue[pixel])
			{
				ch == '\n' ? printf("<br>") : printf("%c", ch);
			} else {
				if (prev_pixel)
					printf("</font>");

				printf("<font style=\"background-color:#%x%x%x\">",
					img->red[pixel],
					img->green[pixel],
					img->blue[pixel]);

				ch == '\n' ? printf("<br>") : printf("%c",ch);

				prev_pixel = pixel;
			}
		}
	}

	/*
	 * Last two pixels were the same, meaning our <font>
	 * tag was never ended.
	 */
	if (img->red[pixel]   == img->red[prev_pixel]   &&
	    img->green[pixel] == img->green[prev_pixel] &&
	    img->blue[pixel]  == img->blue[prev_pixel]
	)
		printf("</font>");

	gdImageDestroy(img);

	return 0;
}

void die(char *fmt, ...)
{
	va_list p;
	extern int errno;
	
	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	va_end(p);

	if (errno)
		perror(NULL);

	exit(1);
}

void usage()
{
	extern char *__progname;

	fprintf(stderr,
		"Usage: %s <image file> <text file>\n\n"
		"<image file> can be either a JPEG or a PNG\n"
		"graphics file, detectable by an appropriate\n"
		"file extension.\n"
		"\n"
		"The resulting HTML output is printed through\n"
		"standard output.\n"
		"\n", __progname);

	exit(0);
}
