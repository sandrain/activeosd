#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <open-osd/libosd.h>
#include <linux/blkdev.h>

#define _LLU(x)			((unsigned long long) (x))

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

static int remove_object(struct osd_dev *od, struct osd_obj_id *obj)
{
	struct osd_request *or = osd_start_request(od, GFP_KERNEL);
	u8 creds[OSD_CAP_LEN];
	int ret;

	if (unlikely(!or))
		return -ENOMEM;

	osdblk_make_credential(creds, obj, osd_req_is_ver1(or));
	osd_req_remove_object(or, obj);
	ret = osdblk_exec(or, creds);
	osd_end_request(or);

	return ret;
}

static u64 inflight;

static void osd_req_callback(struct osd_request *or, void *private)
{
	(void) or;
	(void) private;

	printf("callback\n");

	inflight--;
}

static int do_write_bw(struct osd_dev *od, struct osd_obj_id *obj, u64 bs,
			u64 count, int async)
{
	int ret;
	u64 i;
	u8 creds[OSD_CAP_LEN];
	struct osd_request *or;
	char *buf;
	int fd;
	ssize_t n_read;
	struct timeval before, after;
	double bw;

	buf = malloc(sizeof(char) * bs);
	if (!buf)
		return ENOMEM;

	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0)
		return errno;

	or = osd_start_request(od, GFP_KERNEL);
	osdblk_make_credential(creds, obj, osd_req_is_ver1(or));

	if (async)
		inflight = count;

	gettimeofday(&before, NULL);
	for (i = 0; i < count; i++) {
#if 0
		or = osd_start_request(od, GFP_KERNEL);
		if (ret)
			return ret;

		osdblk_make_credential(creds, obj, osd_req_is_ver1(or));
#endif

		n_read = read(fd, buf, bs);
		if (_LLU(n_read) != _LLU(bs))
			perror("[warning] read failed");

		ret = osd_req_write_kern(or, obj, i*bs, buf, bs);
		if (ret)
			return ret;

		ret = osd_finalize_request(or, 0, creds, NULL);
		if (ret)
			return ret;

		if (async) {
			osd_execute_request_async(or, osd_req_callback,
						(void *) i);
		}
		else {
			ret = osd_execute_request(or);
			if (ret)
				return ret;
		}

#if 0
		osd_end_request(or);
#endif
	}

	while (inflight)
		;

	gettimeofday(&after, NULL);

	osd_end_request(or);

	bw = bs*count;
	bw = bw / ((after.tv_sec - before.tv_sec) + (after.tv_usec - before.tv_usec)*0.000001);
	bw = bw / (1<<20);
	printf("\n\nbw = %.2f MB/s\n", bw);

	return 0;
}

static void *completion_thread(void *arg)
{
	int64_t ret = 0;
	struct osd_dev *od = (void *) arg;

	(void) od;
#if 0
	struct request_queue *q = od->scsi_device->request_queue;

	do {
		ret = bsg_wait_response(q);
		if (ret < 0)
			return (void *) ret;
	} while (ret);
#endif

	return (void *) ret; 
}

static int do_osd_dd_async(const char *dev, struct osd_obj_id *obj, u64 bs,
			u64 count)
{
	int ret;
	struct osd_dev *od;
	pthread_t th;

	ret = osd_open(dev, &od);
	if (ret)
		return ret;

	ret = create_object(od, obj);
	if (ret)
		perror("create_object failed, maybe object already exists?");

	ret = pthread_create(&th, NULL, &completion_thread, od);

	ret = do_write_bw(od, obj, bs, count, 1);
	if (ret)
		perror("do_write_bw failed\n");

	pthread_cancel(th);
	pthread_join(th, (void **) &ret);

	ret = remove_object(od, obj);
	osd_close(od);

	return ret;
}

static int do_osd_dd(const char *dev, struct osd_obj_id *obj, u64 bs,
			u64 count)
{
	int ret;
	struct osd_dev *od;

	ret = osd_open(dev, &od);
	if (ret)
		return ret;

	ret = create_object(od, obj);
	if (ret)
		perror("create_object failed, maybe object already exists?");

	ret = do_write_bw(od, obj, bs, count, 0);
	if (ret)
		perror("do_write_bw failed\n");

	ret = remove_object(od, obj);
	osd_close(od);

	return ret;
}

int main(int argc, char *argv[])
{
	int async = 0;
	u64 bs = 0;
	u64 count = 0;
	char *devpath;
	struct osd_obj_id obj = { .partition = 0x22222, .id = 0x22222 };

	if (argc != 4 && argc != 5) {
		printf("usage: %s <bs> <count> <dev> [async]\n", argv[0]);
		return 1;
	}

	if (argc == 5)
		async = atoi(argv[4]) ? 1 : 0;

	bs = strtoull(argv[1], NULL, 0);
	count = strtoull(argv[2], NULL, 0);
	devpath = argv[3];

	return async ? do_osd_dd_async(devpath, &obj, bs, count)
		: do_osd_dd(devpath, &obj, bs, count);
}

