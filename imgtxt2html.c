/* $Id$ */

#include <stdio.h>
#include <gd.h>
#include <sys/types.h>
#include <regex.h>

void die(char *msg);
void report(char *msg);
void usage(char *msg,int status);

#define IMG_TYPE int

#define IMG_TYPE_PNG 1
#define IMG_TYPE_JPG 2

int main(int argc,char *argv[])
{
	gdImagePtr	img;		/* pointer to image		*/
	FILE		*img_fd,	/* image file descriptor	*/
			*txt_fd,	/* text file descriptor		*/
			*html_fd;	/* HTML file descriptor		*/
	char		f_img[BUFSIZ],	/* image file name		*/
			f_txt[BUFSIZ],	/* text file name		*/
			f_html[BUFSIZ];	/* HTML file name		*/
	int		height,		/* image height			*/
			width,		/* image width			*/
			prev_pixel,	/* previous pixel (cache)	*/
			pixel,		/* pixel identifier		*/
			x,		/* x position			*/
			y,		/* y position			*/
			ch;		/* text file iterator		*/
	IMG_TYPE	img_type;	/* image type			*/

	if (argc != 3)
		usage("",1);

	strlcpy(f_img,argv[1], sizeof f_img);
	strlcpy(f_txt,argv[2], sizeof f_txt);

	txt_fd = fopen(f_txt, "r");

	if (!txt_fd)
		die("Cannot open text file");

	/* use a do here to 'break' out of */
	/*
	 * we should probably make an array of file types
	 * and their corresponding pattern-matching
	 * regexes for scaling
	 */
	do
	{
		int ret;
		char t[BUFSIZ];
		regex_t pat;

		ret = regcomp(&pat, "[.]jpe?g$", REG_ICASE | REG_EXTENDED);

		if ((ret = regexec(&pat, f_img, 0, NULL, 0)) == 0)
		{
			img_type = IMG_TYPE_JPG;

			break;
		}

		ret = regcomp(&pat, "[.]png$", REG_ICASE | REG_EXTENDED);

		if ((ret = regexec(&pat, f_img, 0, NULL, 0)) == 0)
		{
			img_type = IMG_TYPE_PNG;

			break;
		}

		usage("Invalid filename extension", 1);

	} while (0);

	img_fd = fopen(f_img, "rb");

	if (!img_fd)
		die("Cannot open image file");

	img = img_type == IMG_TYPE_JPG ?	gdImageCreateFromJpeg(img_fd) :
						gdImageCreateFromPng(img_fd);

	fclose(img_fd);

	width	= gdImageSX(img);
	height	= gdImageSY(img);

	for (y = 1; y <= height; y++)
	{
		for (x = 1; x <= width; x++)
		{

			pixel	= gdImageGetPixel(img, x, y);
			ch	= fgetc(txt_fd);

			if (prev_pixel
				&& img->red[prev_pixel]	  == img->red[pixel]
				&& img->green[prev_pixel] == img->green[pixel]
				&& img->blue[prev_pixel]  == img->blue[pixel])
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

	if (	   img->red[pixel]   == img->red[prev_pixel]
		&& img->green[pixel] == img->green[prev_pixel]
		&& img->blue[pixel]  == img->blue[prev_pixel]
	)
		printf("</font>");

	gdImageDestroy(img);

	return 0;
}

void die(char *msg)
{
	perror(msg);

	exit(1);
}

void usage(char *msg,int status)
{
	if (strlen(msg))
		fprintf(stderr, "Error: %s\n", msg);

	fprintf(stderr,
		"Usage: imgtxt2html <image file> <text file>\n\n"
		"<image file> can be either a JPEG or a PNG\n"
		"graphics file, detectable by an appropriate\n"
		"file extension.\n\n"
		"The resulting HTML output is printed through\n"
		"standard output.\n\n");

	exit(status);
}

void report(char *msg)
{
	fprintf(stderr, "[DEBUG] %s\n", msg);

	return;
}
