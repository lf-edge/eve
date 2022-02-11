#include <libzfs.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

#include "common.h"

libzfs_handle_ptr libzfsHandle;

int go_libzfs_init() {
	libzfsHandle = libzfs_init();
	return 0;
}

int libzfs_last_error() {
	return libzfs_errno(libzfsHandle);
}

const char *libzfs_last_error_str() {
	return libzfs_error_description(libzfsHandle);
}

int libzfs_clear_last_error() {
	zfs_standard_error(libzfsHandle, EZFS_SUCCESS, "success");
	return 0;
}

property_list_t *new_property_list() {
	property_list_t *r = malloc(sizeof(property_list_t));
	memset(r, 0, sizeof(property_list_t));
	return r;
}

void free_properties(property_list_t *root) {
	property_list_t *tmp = 0;
	while(root) {
		tmp = root->pnext;
		free(root);
		root = tmp;
	}
}

nvlist_ptr new_property_nvlist() {
	nvlist_ptr props = NULL;
	int r = nvlist_alloc(&props, NV_UNIQUE_NAME, 0);
	if ( r != 0 ) {
		return NULL;
	}
	return props;
}

int property_nvlist_add(nvlist_ptr list, const char *prop, const char *value) {
	return nvlist_add_string(list, prop, value);
}

int redirect_libzfs_stdout(int to) {
	int save, res;
	save = dup(STDOUT_FILENO);
	if (save < 0) {
		return save;
	}
	res = dup2(to, STDOUT_FILENO);
	if (res < 0) {
		return res;
	}
	return save;
}

int restore_libzfs_stdout(int saved) {
	int res;
	fflush(stdout);
	res = dup2(saved, STDOUT_FILENO);
	if (res < 0) {
		return res;
	}
	close(saved);
}
