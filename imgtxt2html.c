/* $Id$ */

#include <sys/types.h>

#include <gd.h>
#include <stdarg.h>
#include <stdio.h>

#define TRUE  1
#define FALSE 0

typedef gdImagePtr (*init)(FILE *);

void usage(void);

struct ext_map {
	char *ext;
	init init;
} map[] = {
	{ ".jpg",  gdImageCreateFromJpeg },
	{ ".jpeg", gdImageCreateFromJpeg },
	{ ".png",  gdImageCreateFromPng  },
	{ NULL,    NULL },
};

int
main(int argc, char *argv[])
{
	int width, height, prev_pixel, pixel, x, y, ch;
	char *img_file, *text_file, *html_file, *ep;
	FILE *img_fp, *text_fp, *html_fp;
	struct ext_map *iter;
	init img_init;
	gdImagePtr img;

	if (argc != 3)
		usage();

	img_file  = argv[1];
	text_file = argv[2];

	/* Determine file type. */
	img_init = NULL;
	ep = img_file + strlen(img_file);
	for (iter = map; iter->ext != NULL; iter++)
		if (strcasecmp(ep - strlen(iter->ext), iter->ext) == 0) {
			img_init = iter->init;
			break;
		}

	if (img_init == NULL)
		errx("%s: unsupported image type", img_file);

	/* Gather image data. */
	img_fp = fopen(img_file, "rb");
	if (img_fp == NULL)
		err(1, "open %s", img_file);
	img = (*img_init)(img_fp);
	fclose(img_fp);

	if (img == NULL)
		errx(1, "%s: malformed image", img_file);

	width	= gdImageSX(img);
	height	= gdImageSY(img);

	/* Start gathering text data. */
	if ((text_fp = fopen(text_file, "r")) == NULL)
		err(1, "open %s", text_file);

	/*
	 * Loop from top left to the bottom right.
	 * After we see a pixel, save the color and
	 * compare the next pixel against this color
	 * to reduce HTML output.
	 */
	for (y = 1; y <= height; y++) {
		for (x = 1; x <= width; x++) {
			pixel = gdImageGetPixel(img, x, y);
			ch = fgetc(text_fp);

			if (prev_pixel &&
			    img->red[prev_pixel]   == img->red[pixel]   &&
			    img->green[prev_pixel] == img->green[pixel] &&
			    img->blue[prev_pixel]  == img->blue[pixel]) {
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
	    img->blue[pixel]  == img->blue[prev_pixel])
		printf("</font>");

	gdImageDestroy(img);

	return (0);
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
		"usage: %s <image file> <text file>\n\n"
		"<image file> can be either a JPEG or a PNG\n"
		"graphics file, detectable by an appropriate\n"
		"file extension.\n"
		"\n"
		"The resulting HTML output is printed through\n"
		"standard output.\n"
		"\n", __progname);
	exit(0);
}
