/*
 * osdblk.c - A user-mode program that calls into the osd ULD
 *
 * Copyright (C) 2009 Panasas Inc.  All rights reserved.
 *
 * Authors:
 *   Boaz Harrosh <bharrosh@panasas.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the Panasas company nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <open-osd/libosd.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define OSDBLK_ERR(fmt, a...) fprintf(stderr, "osdblk: " fmt, ##a)
#define OSDBLK_INFO(fmt, a...) printf("osdblk: " fmt, ##a)

#ifdef CONFIG_OSDBLK_DEBUG
#define OSDBLK_DBGMSG(fmt, a...) \
	printf("osdblk @%s:%d: " fmt, __func__, __LINE__, ##a)
#else
#define EXOFS_DBGMSG(fmt, a...) \
	if (0) printf(fmt, ##a);
#endif

static void usage(void)
{
	static char msg[] = {
	"usage: osdblk COMMAND --pid=pid_no --obj=obj_no --length=ob_size /dev/osdX\n"
	"\n"
	"COMMAND is one of: --create | --remove | --resize | --execute\n"
	"--create | -c\n"
	"        Create a new object. If object exist returns error\n"
	"        --length can be used to denote an initial size\n"
	"\n"
	"--remove\n"
	"        remove an existing object. If does not exist does nothing\n"
	"        --length is ignored\n"
	"\n"
	"--resize | -s\n"
	"        Resize an existing object. If does not exist errors\n"
	"        If --length=0 then does nothing (Only check for existance)\n"
	"\n"
	"--execute | -x\n"
	"        Run the active kernel in the target.\n"
	"        This requires oid, result, and kernel parameters.\n"
	"\n"
	"--query | -q\n"
	"        Check the status of an active job.\n"
	"        This requires oid and job id.\n"
	"\n"
	"--pid=pid_no | -p pid_no\n"
	"       pid_no is the partition 64bit number of the object in question\n"
	"       Both 0xabc hex or decimal anotation can be used\n"
	"\n"
	"--oid=obj_no | -o obj_no\n"
	"       obj_no is the object 64bit number of the object in question\n"
	"       Both 0xabc hex or decimal anotation can be used\n"
	"\n"
	"--length=size | -l size\n"
	"       \"size\" is the new size of the object to be set\n"
	"       0xhex or decimal can be used. G, M, K can be appended to the\n"
	"       number to denote base-two Giga Mega or Kilo\n"
	"\n"
	"--result=obj_no | -a obj_no\n"
	"       \"obj_no\" is an object id to store the result of the active\n"
	"       kernel. The object should exist before running the kernel."
	"\n"
	"--kernel=obj_no | -k obj_no\n"
	"       \"obj_no\" is an object id storing an active kernel\n"
	"       The object should exist before running the kernel.\n"
	"\n"
	"--job=job_no | -j job_no\n"
	"       \"job_no\" is a job identification number.\n"
	"\n"
	"/dev/osdX is the osd LUN (char-dev) to use containing the object\n"
	"\n"
	"Description: Create Remove or Resize an OSD object on an OSD LUN\n"
	"             The object can later be used, for example, by the\n"
	"             osdblk device driver\n"
	};

	printf(msg);
}

#define _LLU(x) ((unsigned long long)x)

#if 0
static u64 ullwithGMK(char *optarg)
{
	char *pGMK;
	u64 mul;
	u64 val = strtoll(optarg, &pGMK, 0);

	switch (*pGMK) {
	case 'K':
	case 'k':
		mul = 1024LLU;
		break;
	case 'M':
		mul = 1024LLU * 1024LLU;
		break;
	case 'G':
		mul = 1024LLU * 1024LLU * 1024LLU;
		break;
	default:
		mul = 1;
	}

	return val * mul;
}

/* endian functions */
static uint32_t swab32(uint32_t d)
{
	return  (d & (uint32_t) 0x000000ffUL) << 24 |
		(d & (uint32_t) 0x0000ff00UL) << 8  |
		(d & (uint32_t) 0x00ff0000UL) >> 8  |
		(d & (uint32_t) 0xff000000UL) >> 24;
}

static uint64_t get_ntohll_be(const void *d)
{
	return *(const uint64_t *) d;
}

/*
 * Things are not aligned in the current osd2r00, but they probably
 * will be soon.  Assume 4-byte alignment though.
 */
static uint64_t get_ntohll_le(const void *d)
{
	uint32_t d0 = swab32(*(const uint32_t *) d);
	uint32_t d1 = swab32(*(const uint32_t *) ((long)d + 4));

	return (uint64_t) d0 << 32 | d1;
}
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define get_ntohll     get_ntohll_le
#else
#define get_ntohll     get_ntohll_be
#endif


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
	if (ret) {
		OSDBLK_ERR("Error: Faild to osd_finalize_request() => %d\n",
			   ret);
		return ret;
	}

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

static int do_link(struct osd_dev *od, u64 pid, u64 oid, u64 cid)
{
	int ret;
	u8 creds[OSD_CAP_LEN];
	struct osd_request *or = osd_start_request(od, GFP_KERNEL);
	struct osd_obj_id obj;
	__be64 be_cid = cpu_to_be64(cid);
	struct osd_attr membership = ATTR_SET(OSD_APAGE_OBJECT_COLLECTIONS, 1,
						sizeof(be_cid), &be_cid);

	if (unlikely(!or))
		return -ENOMEM;

	obj.partition = pid;
	obj.id = oid;

	osdblk_make_credential(creds, &obj, osd_req_is_ver1(or));

	osd_req_set_attributes(or, &obj);
	osd_req_add_set_attr_list(or, &membership, 1);

	ret = osdblk_exec(or, creds);
	osd_end_request(or);

	if (ret)
		return ret;

	OSDBLK_INFO("Linked: obj(pid=0x%llx oid=0x%llx) to "
		    "collection(cid=0x%llx\n)",
		    _LLU(obj.partition), _LLU(obj.id), _LLU(cid));

	return 0;
}

static int link_obj_to_collection(char *path, u64 pid, u64 oid, u64 cid)
{
	struct osd_dev *od;
	int ret;

	ret = osd_open(path, &od);
	if (ret)
		return ret;

	ret = do_link(od, pid, oid, cid);

	osd_close(od);

	/* osd lib has Kernel API which return negative errors */
	return -ret;
}

int main(int argc, char *argv[])
{
	struct option opt[] = {
		{.name = "pid", .has_arg = 1, .flag = NULL, .val = 'p'},
		{.name = "oid", .has_arg = 1, .flag = NULL, .val = 'o'},
		{.name = "cid", .has_arg = 1, .flag = NULL, .val = 'c'},

		{.name = 0, .has_arg = 0, .flag = 0, .val = 0} ,
	};
	u64 pid, oid, cid;
	char op;
	int err;

	pid = oid = cid = 0;

	while ((op = getopt_long(argc, argv, "p:c:o:", opt, NULL)) != -1) {
		switch (op) {
		case 'c':
			cid = strtoll(optarg, NULL, 0);
			break;
		case 'p':
			pid = strtoll(optarg, NULL, 0);
			break;
		case 'o':
			oid = strtoll(optarg, NULL, 0);
			break;
		default:
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0) {
		usage();
		return 1;
	}

	if (!pid || !oid || !cid) {
		usage();
		return 1;
	}

	err = link_obj_to_collection(argv[0], pid, oid, cid);
	if (err)
		OSDBLK_ERR("Error: %s\n", strerror(err));

	return err;
}
