#include <unistd.h>

#include <scsi/scsi_ioctl.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scsiexe.h"

/***************************************************************************
 * name: init_io_hdr
 * parameter:
 * function: initialize the sg_io_hdr struct fields with the most common
 * 			 value
 * **************************************************************************/
struct  sg_io_hdr * init_io_hdr() {

	struct sg_io_hdr * p_scsi_hdr = (struct sg_io_hdr *)malloc(sizeof(struct sg_io_hdr));
	memset(p_scsi_hdr, 0, sizeof(struct sg_io_hdr));
	if (p_scsi_hdr) {
		p_scsi_hdr->interface_id = 'S'; /* this is the only choice we have! */
		p_scsi_hdr->flags = SG_FLAG_LUN_INHIBIT; /* this would put the LUN to 2nd byte of cdb*/
	}

	return p_scsi_hdr;
}

void destroy_io_hdr(struct sg_io_hdr * p_hdr) {
	if (p_hdr) {
		free(p_hdr);
	}
}

void set_xfer_data(struct sg_io_hdr * p_hdr, void * data, unsigned int length) {
	if (p_hdr) {
		p_hdr->dxferp = data;
		p_hdr->dxfer_len = length;
	}
}

void set_sense_data(struct sg_io_hdr * p_hdr, unsigned char * data,
		unsigned int length) {
	if (p_hdr) {
		p_hdr->sbp = data;
		p_hdr->mx_sb_len = length;
	}
}

/***************************************************************************
 * name: execute_Inquiry
 * parameter:
 * 		fd:			file descripter
 * 		page_code:	cdb page code
 * 		evpd:			cdb evpd
 * 		p_hdr:		poiter to sg_io_hdr struct
 * function: make Inquiry cdb and execute it.
 * **************************************************************************/
int execute_Inquiry(int fd, int page_code, int evpd, struct sg_io_hdr * p_hdr) {
	unsigned char cdb[6];

	/* set the cdb format */
	cdb[0] = 0x12; /*This is for Inquery*/
	cdb[1] = evpd & 1;
	cdb[2] = page_code & 0xff;
	cdb[3] = 0;
	cdb[4] = 0xff;
	cdb[5] = 0; /*For control filed, just use 0*/
	
	p_hdr->dxfer_direction = SG_DXFER_FROM_DEV;
	p_hdr->cmdp = cdb;
	p_hdr->cmd_len = 6;

	int ret = ioctl(fd, SG_IO, p_hdr);
	if (ret<0) {
		printf("Sending SCSI Command failed.\n");
		close(fd);
		exit(1);
	}

	return p_hdr->status;
}

int execute_kernel_test(int fd, struct sg_io_hdr *p_hdr)
{
	unsigned char cdb[10];

	memset(cdb, 0, 10);
	cdb[0] = 0x7f;
	cdb[1] = 0x1e;

	p_hdr->dxfer_direction = SG_DXFER_NONE;
	p_hdr->cmdp = cdb;
	p_hdr->cmd_len = 6;

	int ret = ioctl(fd, SG_IO, p_hdr);
	if (ret<0) {
		printf("Sending SCSI Command failed.\n");
		close(fd);
		exit(1);
	}

	return p_hdr->status;
}

