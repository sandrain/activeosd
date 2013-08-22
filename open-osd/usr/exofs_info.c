/**	exofs_info.c
 *
 * Dump the object information for a given file.
 */

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "mkexofs.h"

static void usage(void)
{
	printf("exofs-info <filename>\n");
}

static void _make_credential(u8 cred_a[OSD_CAP_LEN],
			     const struct osd_obj_id *obj)
{
	osd_sec_init_nosec_doall_caps(cred_a, obj, false, true);
}

static int _check_ok(struct osd_request *or)
{
	struct osd_sense_info osi;
	int ret = osd_req_decode_sense(or, &osi);

	if (unlikely(ret)) { /* translate to Linux codes */
		if (osi.additional_code == scsi_invalid_field_in_cdb) {
			if (osi.cdb_field_offset == OSD_CFO_STARTING_BYTE)
				ret = -EFAULT;
			if (osi.cdb_field_offset == OSD_CFO_OBJECT_ID)
				ret = -ENOENT;
			else
				ret = -EINVAL;
		} else if (osi.additional_code == osd_quota_error)
			ret = -ENOSPC;
		else
			ret = -EIO;
	}

	return ret;
}

static int dump_file_info(const char *path)
{
	int ret;
	ino_t ino;
	struct stat stbuf;
	struct osd_request *or;
	uint8_t cred_a[OSD_CAP_LEN];
	struct exofs_fcb inode;
	struct osd_attr attr;
	uint32_t i_generation;

	ret = stat(path, &stbuf);
	if (ret) {
		ret = errno;
		goto out;
	}
	ino = stbuf.st_ino;

	or = osd_start_request(od, GFP_KERNEL);
	if (unlikely(!or))
		return -ENOMEM;

	_make_credential(cred_a, obj);
out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (argc != 2) {
		usage();
		return 1;
	}

	ret = dump_file_info(argv[1]);

	if (ret) {
		fprintf(stderr, "dump_file_info failed (%d): %s\n",
				ret, strerror(ret));
	}

	return ret;
}

