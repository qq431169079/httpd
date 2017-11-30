/* 
**  apr_flashapp_image.h -- Apache  flashapp
*/ 
#define IMG_RET_OK 0
#define IMG_RET_ERR_BAD_DATA_FORMAT 1
#define IMG_RET_ERR_OUT_OF_MEM 2
#define IMG_RET_ERR_UNKNOWN 3
#define IMG_RET_ERR_NOT_IMPL_YET 4
#define IMG_RET_ERR_POSSIBLE_LOOK_CHANGE 5
#define IMG_RET_TOO_SMALL 32
#define IMG_RET_ERR_OTHER 33
#define IMG_RET_TOO_EXPANSIVE 34
#define IMG_RET_NO_AVAIL_TARGET 35
#define IMG_RET_TOO_BIG 36
#define IMG_RET_SOFTWARE_BUG 37


/* 1GB roof for max_raw_size */
#define MAX_RAW_SIZE_ROOF 0x3fffffffLL

// minimal image file size to _bother_ trying to recompress
#define MIN_INSIZE_GIF 100
#define MIN_INSIZE_PNG 100
#define MIN_INSIZE_JPEG 600
#define MIN_INSIZE_JP2K 800
#define MIN_INSIZE_TO_JPEG 600
#define MIN_INSIZE_TO_JP2K 800

#define MAX_UNCOMPRESS_IMAGE_RATIO 500


enum enum_content_type {OTHER_CONTENT, IMG_PNG, IMG_GIF, IMG_JPEG, IMG_JP2K, TEXT_HTML, TEXT_CSS, APPLICATION_JAVASCRIPT};
#define t_content_type enum enum_content_type

enum enum_original_ct {OCT_UNDEFINED, OCT_PALETTE, OCT_GRAY, OCT_RGB, OCT_YUV}; // original color type (does not consider alpha)
#define t_original_ct enum enum_original_ct

typedef struct {
	unsigned char * raster;	//For paletted images
	unsigned char * palette;
	unsigned char * bitmap;	//For grayscale/truecolor RGB images (always present and the default bitmap)
	unsigned char * bitmap_yuv; //For truecolor YUV images (allocated on demand)
	int pal_entries;
	int width, height;
	int pal_bpp, bpp;
	int o_depth_R, o_depth_G, o_depth_B;	/* original bit depth of each component before recompression */
	int o_depth_Y, o_depth_U, o_depth_V;	/* same as above */
	int o_depth_A;				/* same as above */
	t_original_ct o_color_type;		/* original color type before recompression */
	int opt_pal_transp;			/* total of pixels with alpha data, when palette is optimized */
} raw_bitmap;

