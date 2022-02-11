#include <libzfs.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <sys/fs/zfs.h>

#include "common.h"
#include "zpool.h"


uint64_t set_zpool_vdev_online(zpool_list_t *pool, const char *path, int flags) {
	vdev_state_t newstate = VDEV_STATE_UNKNOWN;
	zpool_vdev_online(pool->zph, path, flags, &newstate);
	return newstate;
}

int set_zpool_vdev_offline(zpool_list_t *pool, const char *path, boolean_t istmp, boolean_t force) {
	int ret = 0;
	// if (force) {
	// 	uint64_t guid = zpool_vdev_path_to_guid(pool->zph, path);
	// 	vdev_aux_t aux;
	// 	if (istmp == B_FALSE) {
	// 		/* Force the fault to persist across imports */
	// 		aux = VDEV_AUX_EXTERNAL_PERSIST;
	// 	} else {
	// 		aux = VDEV_AUX_EXTERNAL;
	// 	}

	// 	if (guid == 0 || zpool_vdev_fault(pool->zph, guid, aux) != 0)
	// 		ret = 1;
	// } else {
		if (zpool_vdev_offline(pool->zph, path, istmp) != 0)
			ret = 1;
	// }
	return ret;
}

