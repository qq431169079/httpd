/* 
**  apr_flashapp_image.c -- Apache  flashapp
*/ 

#include <sys/msg.h>
#include <ctype.h>
#include "ap_mpm.h"
#include "http_log.h"
#include "apr_flash_image.h"
#include "apr_md5.h"
#include "util_time.h"
#include "apr_time.h"



t_content_type detect_type (char *line, int len)
{
	t_content_type image = OTHER_CONTENT;

	if (len < 4) return OTHER_CONTENT;
    // Check for image signatures
	if ((line[0] == -1) && (line[1] == -40) &&
		(line[2] == -1) && (line[3] == -32))
		image = IMG_JPEG;
	else if ((line[0] == 'G') && (line[1] == 'I') &&
		     (line[2] == 'F') && (line[3] == '8'))
		image = IMG_GIF;
	else if ((line[0] == -119) && (line[1] == 'P') &&
		     (line[2] == 'N') && (line[3] == 'G'))
		image = IMG_PNG;
#ifdef JP2K
	// TODO: improve JP2K detection
	else if ((line[4] == 'j') && (line[5] == 'P'))
		image = IMG_JP2K;
#endif
	return image;
}


/* Recompress pictures.
 * inbuf/insize: original compressed image (jpeg/png/etc)
 * outb/outl: new recompressed image (to jpeg/png etc).
 *            a buffer will be malloc()'ed automatically in this case.
 *
 * Returns: IMG_RET_OK, recompression successful. Or error code.
 *
 * Note: this routine was rewritten (the old one is used in versions <= 3.0.x)
 *       and does not have the exact same behavior as the previous one.
 */
/* FIXME: This routine does not support data > 2GB (limited to int) */
/* FIXME: inbuf AND outb cannot be safely free()'d afterwards!
          when compression fails inbuf==outb, so trying to free() both will fail. */
int compress_image (http_headers *serv_hdr, http_headers *client_hdr, char *inbuf, ZP_DATASIZE_TYPE insize, char **outb, ZP_DATASIZE_TYPE *outl){
	int st = IMG_RET_ERR_OTHER;
	int pngstatus = IMG_RET_ERR_OTHER;
	int jp2status = IMG_RET_ERR_OTHER;
	int jpegstatus = IMG_RET_ERR_OTHER;
	t_content_type outtype = OTHER_CONTENT;
	int jpeg_q;
	raw_bitmap *bmp = NULL;
	long long int max_raw_size;
	t_content_type detected_ct;
	t_content_type source_type;
	t_content_type target_lossy;
	t_content_type target_lossless = IMG_PNG; /* only PNG is available */
	int try_lossless = 1, try_lossy = 1;
	int has_transparency = 0;
	char *buf_lossy = NULL, *buf_lossless = NULL;
	int buf_lossy_len, buf_lossless_len;
	int max_outlen;
	int lossy_status, lossless_status;
	const int *j2bitlenYA, *j2bitlenRGBA, *j2bitlenYUVA, *j2csamplingYA, *j2csamplingRGBA, *j2csamplingYUVA;
	int source_is_lossless = 0;	/* !=0 if source is gif or png */

	// "rate" below: JP2 rate, the native compression setting of JP2
	// tries to emulate JPEG's quality setting to JP2, and this
	// var represents the 'real thing' which is hidden from the user.
	float rate = -1.0;
	int jp2_q;


	detected_ct = detect_type (inbuf, insize);
	if (detected_ct != OTHER_CONTENT && serv_hdr != NULL)
		serv_hdr->type = detected_ct;

	//source_type = serv_hdr->type;
	source_type = detected_ct;

	max_raw_size = insize * MAX_UNCOMPRESS_IMAGE_RATIO;

	/* max_raw_size is undefined, set it to the internal roof then */
	if (max_raw_size == 0) {
		debug_log_printf ("WARNING: MaxUncompressedImageRatio set to 0 (no " \
			"ratio limit). Using internal absolute limit of %lld bytes.\n", \
			MAX_RAW_SIZE_ROOF);
		max_raw_size = MAX_RAW_SIZE_ROOF;
	}

	/* max_raw_size beyond roof, set it to internal roof instead */
	if (max_raw_size > MAX_RAW_SIZE_ROOF) {
		debug_log_printf ("WARNING: Max image size (%lld) bigger than internal " \
			"roof (%lld). Using internal roof instead.\n", max_raw_size, \
			MAX_RAW_SIZE_ROOF);
		max_raw_size = MAX_RAW_SIZE_ROOF;
	}

	debug_log_puts ("Starting image decompression...");

	switch (source_type) {
		case IMG_PNG:
			if (insize >= MIN_INSIZE_PNG)
				st = png2bitmap (inbuf, insize, &bmp, max_raw_size);
			else
				st = IMG_RET_TOO_SMALL;
			source_is_lossless = 1;
			break;
		case IMG_GIF:
			if (insize >= MIN_INSIZE_GIF)
				st = gif2bitmap (inbuf, insize, &bmp, max_raw_size);
			else
				st = IMG_RET_TOO_SMALL;
			source_is_lossless = 1;
			break;
		case IMG_JPEG:
			if (insize >= MIN_INSIZE_JPEG)
				st = jpg2bitmap (inbuf, insize, &bmp, max_raw_size);
			else
				st = IMG_RET_TOO_SMALL;
			break;
#ifdef JP2K
		case IMG_JP2K:
			if ((insize >= MIN_INSIZE_JP2K) || (ForceOutputNoJP2))
				st = jp22bitmap (inbuf, insize, &bmp, max_raw_size);
			else
				st = IMG_RET_TOO_SMALL;
			break;
#endif
		default:
			debug_log_puts ("ERROR: Unrecognized image format!\n");
			st = IMG_RET_ERR_OTHER;
			break;
	}

	// error, forward unchanged
	if (st != IMG_RET_OK) {
		debug_log_puts ("Error while decompressing image.");
		*outb = inbuf;
		*outl = insize;
#ifdef IMAGE_MEM_REDUCE
		compress_image_freemem(source_type, bmp);
#endif
		return st;
	}
	if (bmp->o_color_type == OCT_PALETTE) {
		debug_log_printf ("Image parms (palette) -- w: %d, h: %d, " \
			"palette with %d colors, pal_bpp: %d.\n", \
			bmp->width, bmp->height, bmp->pal_entries, bmp->pal_bpp);
	} else {
		debug_log_printf ("Image parms (non-palette) -- w: %d, h: %d, bpp: %d\n", \
			bmp->width, bmp->height, bmp->bpp);
	}

	optimize_palette (bmp);
	optimize_alpha_channel (bmp);

	/*
	 * STRATEGY DECISIONS
	 */

	debug_log_puts ("Deciding image compression strategy...");

	/* does it have transparency? */
	if (bmp->raster != NULL) {
		/* palette image */
		if ((bmp->pal_bpp == 2) || (bmp->pal_bpp == 4))
			has_transparency = 1;
	} else {
		/* non-palette image */
		if ((bmp->bpp == 2) || (bmp->bpp == 4))
			has_transparency = 1;
	}

	/* which lossy format to use? */
#ifdef JP2K
	if (ProcessToJP2 && (! ForceOutputNoJP2) && \
		((! JP2OutRequiresExpCap) || (JP2OutRequiresExpCap && (client_hdr != NULL && client_hdr->client_explicity_accepts_jp2)))) {
		target_lossy = IMG_JP2K;
	} else {
		target_lossy = IMG_JPEG;
	}
#else
	target_lossy = IMG_JPEG;
#endif

	/* is lossy suitable for this picture? */
#ifdef JP2K
	if (target_lossy == IMG_JP2K) {
		jp2_q = getJP2ImageQuality (bmp->width, bmp->height);
		if ((jp2_q == 0) || (insize < MIN_INSIZE_TO_JP2K))
			try_lossy = 0;
	}
#endif
	if (target_lossy == IMG_JPEG) {
		jpeg_q = getImageQuality (bmp->width, bmp->height);
		if ((jpeg_q == 0) || (insize < MIN_INSIZE_TO_JPEG)) {
			try_lossy = 0;
		} else if (has_transparency) {
			if (AllowLookCh)
				remove_alpha_channel (bmp);
			else
				try_lossy = 0;
		}
	}

	/* compressed data may not be bigger than max_outlen */
	max_outlen = insize - 1;

#ifdef JP2K
	/* should we convert from jp2k even if the final size is bigger? */
	if ((source_type == IMG_JP2K) && (ForceOutputNoJP2)) {
		// up to 100%+500bytes of uncompressed bitmap, otherwise it's an abnomaly
		max_outlen = (bmp->width * bmp->height * bmp->bpp) + 500;
	}
#endif

	/* let's try saving some CPU load:
	   is it worth trying lossless compression? */
	if ((try_lossless != 0) && (try_lossy != 0) && (source_is_lossless == 0)) {
		try_lossless = 0;
	}

	/* no viable target? return */
	if ((try_lossy == 0) && (try_lossless == 0)) {
		debug_log_puts ("No viable image target (lossy or lossless).");
#ifdef IMAGE_MEM_REDUCE
		compress_image_freemem(source_type, bmp);
#endif
		return IMG_RET_NO_AVAIL_TARGET;
	}

	/*
	 * END OF STRATEGY DECISIONS
	 */

	debug_log_puts ("Strategy defined. Continuing...");


	if (try_lossy) {
		buf_lossy_len = max_outlen;

		/* for lossy, full RGB image is required */
		if (bmp->bitmap == NULL)
			depalettize (bmp);
	}
	if (try_lossless) {
		/* bitmap2png requires a preallocated buffer */
		buf_lossless = (char *) malloc (sizeof (char) * max_outlen);
		buf_lossless_len = max_outlen;
	}

	if (ConvertToGrayscale && (bmp->bitmap != NULL)) {
		debug_log_puts ("Converting image to grayscale...");
		rgb2gray (bmp);
	}

#ifdef JP2K
	if ((try_lossy) && (target_lossy == IMG_JP2K)) {
		debug_log_puts ("Attempting JP2K compression...");

		// get the components' bit depth specifically for this image (based on image dimensions)
		j2bitlenYA = getJP2KBitLenYA (bmp->width, bmp->height);
		j2bitlenRGBA = getJP2KBitLenRGBA (bmp->width, bmp->height);
		j2bitlenYUVA = getJP2KBitLenYUVA (bmp->width, bmp->height);

		// get the components' sampling (scaling) parameters specifically for this image (based on image dimensions)
		j2csamplingYA = getJP2KCSamplingYA (bmp->width, bmp->height);
		j2csamplingRGBA = getJP2KCSamplingRGBA (bmp->width, bmp->height);
		j2csamplingYUVA = getJP2KCSamplingYUVA (bmp->width, bmp->height);

		rate = estimate_jp2rate_from_quality (bmp, jp2_q, \
			JP2Colorspace, j2bitlenYA, j2bitlenRGBA, j2bitlenYUVA, \
			j2csamplingYA, j2csamplingRGBA, j2csamplingYUVA);

		if (rate * (float) calculate_jp2_rawsize (bmp, JP2Colorspace, \
			j2bitlenYA, j2bitlenRGBA, j2bitlenYUVA, j2csamplingYA, \
			j2csamplingRGBA, j2csamplingYUVA, 0) <= (float) max_outlen) {

			jp2status = bitmap2jp2 (bmp, rate, &buf_lossy, &buf_lossy_len, \
				JP2Colorspace, j2bitlenYA, j2bitlenRGBA, \
				j2bitlenYUVA, j2csamplingYA, j2csamplingRGBA, \
				j2csamplingYUVA);
		} else {
			jp2status = IMG_RET_TOO_BIG;
		}
	} else {
		jp2status = IMG_RET_ERR_OTHER;
	}
#endif

	if ((try_lossy) && (target_lossy == IMG_JPEG)) {
		debug_log_puts ("Attempting JPEG compression...");
		jpegstatus = bitmap2jpg (bmp, jpeg_q, &buf_lossy, &buf_lossy_len);
	}

	/* try_lossless implies PNG */
	if (try_lossless != 0) {
		debug_log_puts ("Attempting PNG compression...");
		pngstatus = bitmap2png (bmp, &buf_lossless, &buf_lossless_len);
		debug_log_printf("the head of new png,%d %d %d %d\n",buf_lossless[0],buf_lossless[1],buf_lossless[2],buf_lossless[3]);
	}

	debug_log_printf ("Compression return codes -- JP2K:%d JPEG:%d PNG:%d\n", jp2status, jpegstatus, pngstatus);

	lossless_status = pngstatus;
	if (target_lossy == IMG_JPEG)
		lossy_status = jpegstatus;
	else
		lossy_status = jp2status;

	/* decide which compressed version to use, or none */
	if ((lossless_status == IMG_RET_OK) && (lossy_status == IMG_RET_OK)) {
		/* TODO: add some fuzzy logic here
		  (smallest size is not always the best choice) */
		if (buf_lossy_len < buf_lossless_len) {
			outtype = target_lossy;
		} else {
			outtype = target_lossless;
		}
	} else if (lossless_status == IMG_RET_OK) {
		outtype = target_lossless;
	} else if (lossy_status == IMG_RET_OK) {
		outtype = target_lossy;
	} else {
		outtype = OTHER_CONTENT;
	}

	/* select buffer and discard the other one (or both) */
	if (outtype == target_lossy) {
		*outb = buf_lossy;
		*outl = buf_lossy_len;
		if (buf_lossless != NULL)
			free (buf_lossless);
	} else if (outtype == target_lossless) {
		*outb = buf_lossless;
		*outl = buf_lossless_len;
		if (buf_lossy != NULL)
			free (buf_lossy);
	} else {
		*outb = inbuf;
		*outl = insize;
		if (buf_lossy != NULL)
			free (buf_lossy);
		if (buf_lossless != NULL)
			free (buf_lossless);
	}

	//if (serv_hdr->where_content_type > 0){
	if (serv_hdr != NULL && serv_hdr->where_content_type > 0){
		if(outtype != OTHER_CONTENT)
			switch(outtype){
				case IMG_JP2K:
					serv_hdr->hdr[serv_hdr->where_content_type] =
						"Content-Type: image/jp2";
					break;
				case IMG_JPEG:
					serv_hdr->hdr[serv_hdr->where_content_type] =
						"Content-Type: image/jpeg";
					break;
				case IMG_PNG:
					serv_hdr->hdr[serv_hdr->where_content_type] =
						"Content-Type: image/png";
					break;
			}
	}

exit:

#ifdef IMAGE_MEM_REDUCE
	compress_image_freemem(source_type, bmp);
#endif
	return IMG_RET_OK;
}
