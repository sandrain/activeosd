/**
 * sg command issue test
 */

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <scsi/scsi_ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct sg_io_hdr *init_io_hdr(void)
{
	struct sg_io_hdr *psh = malloc(sizeof(*psh));

	if (psh) {
		memset(psh, 0, sizeof(*psh));
		psh->interface_id = 'S';
		psh->flags = SG_FLAG_LUN_INHIBIT;
	}

	return psh;
}

static void destroy_io_hdr(struct sg_io_hdr *hp)
{
	if (hp)
		free(hp);
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct sg_io_hdr *hp = init_io_hdr();

	if (!hp)
		return -1;

	destroy_io_hdr(hp);

	return 0;
}

