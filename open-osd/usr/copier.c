#include <open-osd/libosd.h>

#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define	TESTBUFSIZE		(1<<20)		/** 1MB */

#define _LLU(x)			((unsigned long long) (x))

static char buf[TESTBUFSIZE];
static struct osd_obj_id obj_src = {
	.partition = 0x33333,
	.id = 0x11111,
};
static struct osd_obj_id obj_dst = {
	.partition = 0x33333,
	.id = 0x22222,
};

static void osdblk_make_credential(u8 *creds, struct osd_obj_id *obj,
				   bool is_v1)
{
	osd_sec_init_nosec_doall_caps(creds, obj, false, is_v1);
}

static int osdblk_exec(struct osd_request *or, u8 *cred)
{
	struct osd_sense_info osi;
	int ret;

	ret = osd_finalize_request(or, 0, cred, NULL);
	if (ret)
		return ret;

	osd_execute_request(or);
	ret = osd_req_decode_sense(or, &osi);

	if (ret) { /* translate to Linux codes */
		if (osi.additional_code == scsi_invalid_field_in_cdb) {
			if (osi.cdb_field_offset == OSD_CFO_STARTING_BYTE)
				ret = 0; /*this is OK*/
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

static int create_object(struct osd_dev *od, struct osd_obj_id *obj)
{
	struct osd_request *or = osd_start_request(od, GFP_KERNEL);
	u8 creds[OSD_CAP_LEN];
	int ret;
	struct osd_attr attr;
	u64 oid = obj->id;
	int nelem = 1;
	void *iter = NULL;

	if (unlikely(!or))
		return -ENOMEM;

	osdblk_make_credential(creds, obj, osd_req_is_ver1(or));

	/* Create partition OK to fail (all ready exist) */
	osd_req_create_partition(or, obj->partition);
	ret = osdblk_exec(or, creds);
	osd_end_request(or);

	if (ret)
		printf("pid=0x%llx exists\n", _LLU(obj->partition));

	or = osd_start_request(od, GFP_KERNEL);
	if (unlikely(!or))
		return -ENOMEM;

	osd_req_create_object(or, obj);

	if (obj->id == 0) {
		/** we need to retrieve the collection id allocated */
		attr.attr_page = OSD_APAGE_CURRENT_COMMAND;
		attr.attr_id = OSD_APAGE_OBJECT_COLLECTIONS;
		attr.len = sizeof(__be64);
		attr.val_ptr = NULL;
		ret = osd_req_add_get_attr_list(or, &attr, 1);
	}

	ret = osdblk_exec(or, creds);
	if (ret) {
		osd_end_request(or);
		return ret;
	}

	if (obj->id == 0) {
		osd_req_decode_get_attr_list(or, &attr, &nelem, &iter);
		oid = get_unaligned_be64(attr.val_ptr);
		obj->id = oid;
	}

	osd_end_request(or);
	return 0;
}

static int populate_object(struct osd_dev *od, struct osd_obj_id *obj,
			const u64 size)
{
	int ret;
	struct osd_request *or;
	u8 creds[OSD_CAP_LEN];
	u64 n_written = 0, to_be_written;
	FILE *fp;

	fp = fopen("/dev/urandom", "r");
	if (!fp)
		return errno;

	while (n_written < size) {
		to_be_written = min(_LLU(TESTBUFSIZE), _LLU(size - n_written));

		if (1 != fread(buf, to_be_written, 1, fp))
			return errno;

		or = osd_start_request(od, GFP_KERNEL);
		if (unlikely(!or))
			return -ENOMEM;

		osdblk_make_credential(creds, obj, osd_req_is_ver1(or));

		ret = osd_req_write_kern(or, obj, n_written, buf,
					to_be_written);
		if (ret)
			return ret;

		ret = osdblk_exec(or, creds);
		osd_end_request(or);
		if (ret)
			return ret;

		n_written += to_be_written;
	}

	fclose(fp);

	return 0;
}

static int cross_copy_object(struct osd_dev *ods, struct osd_dev *odd,
			struct osd_obj_id *src, struct osd_obj_id *dst)
{
	int ret;
	int exit = 0;
	struct osd_request *ors, *ord;
	u8 credss[OSD_CAP_LEN], credsd[OSD_CAP_LEN];
	u64 total_read = 0, n_read = 0;
	u64 total_write = 0, n_written = 0;
	struct osd_sense_info osi;

	while (1) {
		ors = osd_start_request(ods, GFP_KERNEL);
		ord = osd_start_request(odd, GFP_KERNEL);
		assert(ors && ord);

		osdblk_make_credential(credss, src, osd_req_is_ver1(ors));
		osdblk_make_credential(credsd, dst, osd_req_is_ver1(ord));

		/**
		 * read the source
		 */
		ret = osd_req_read_kern(ors, src, total_read, buf, TESTBUFSIZE);
		assert(0 == ret);

		ret = osd_finalize_request(ors, 0, credss, NULL);
		assert(0 == ret);

		ret = osd_execute_request(ors);
		if (ret) {
			ret = osd_req_decode_sense(ors, &osi);
			if (osi.additional_code == osd_read_past_end_of_user_object)
			{
				n_read = osi.command_info;
				exit = 1;
			}
		}
		else
			n_read = TESTBUFSIZE;

		total_read += n_read;
		osd_end_request(ors);

		if (n_read == 0)
			break;	/** no more write necessary */

		/**
		 * write the dest
		 */
		ret = osd_req_write_kern(ord, dst, total_write, buf, n_read);
		assert(0 == ret);

		ret = osd_finalize_request(ord, 0, credsd, NULL);
		assert(0 == ret);

		ret = osd_execute_request(ord);
		assert(0 == ret);

		ret = osd_req_decode_sense(ord, &osi);
		if (ret) {
			if (osi.additional_code == scsi_invalid_field_in_cdb) {
				if (osi.cdb_field_offset == OSD_CFO_STARTING_BYTE)
					ret = 0; /*this is OK*/
				if (osi.cdb_field_offset == OSD_CFO_OBJECT_ID)
					ret = -ENOENT;
				else
					ret = -EINVAL;
			} else if (osi.additional_code == osd_quota_error)
				ret = -ENOSPC;
			else
				ret = -EIO;
			printf("%d\n", -ret);
			assert(0);
		}

		osd_end_request(ord);

		n_written = n_read;
		total_write += n_written;
		if (exit)
			break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	const char *osd_src_path, *osd_dst_path;
	struct osd_dev *osd_src, *osd_dst;
	u64 test_size;

	if (argc != 6) {
		printf("usage: %s <src osd> <dst osd> <testsize> <src> <dst>\n", argv[0]);
		return 1;
	}

	osd_src_path = argv[1];
	osd_dst_path = argv[2];
	test_size = strtoull(argv[3], NULL, 0);
	obj_src.id = strtoull(argv[4], NULL, 0);
	obj_dst.id = strtoull(argv[5], NULL, 0);

	/** open devices */
	ret = osd_open(osd_src_path, &osd_src);
	ret |= osd_open(osd_dst_path, &osd_dst);
	assert(0 == ret);

	/** create objects */
	ret = create_object(osd_src, &obj_src);
	ret |= create_object(osd_dst, &obj_dst);
	assert(0 == ret);

	/** populate the source object */
	ret = populate_object(osd_src, &obj_src, test_size);
	assert(0 == ret);

	/** copy object to other dev */
	ret = cross_copy_object(osd_src, osd_dst, &obj_src, &obj_dst);
	assert(0 == ret);

	/** close devices */
	osd_close(osd_dst);
	osd_close(osd_src);

	return ret;
}

