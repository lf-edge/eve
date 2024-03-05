/* C wrappers around some zfs calls and C in general that should simplify
 * using libzfs from go language, and make go code shorter and more readable.
 */

#include <libzfs.h>
#include <libzfs/sys/zfs_context.h>
#include <libzutil.h>
#include <thread_pool.h>

#include <memory.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "zpool.h"

char *sZPOOL_CONFIG_VERSION = ZPOOL_CONFIG_VERSION;
char *sZPOOL_CONFIG_POOL_NAME = ZPOOL_CONFIG_POOL_NAME;
char *sZPOOL_CONFIG_POOL_STATE = ZPOOL_CONFIG_POOL_STATE;
char *sZPOOL_CONFIG_POOL_TXG = ZPOOL_CONFIG_POOL_TXG;
char *sZPOOL_CONFIG_POOL_GUID = ZPOOL_CONFIG_POOL_GUID;
char *sZPOOL_CONFIG_CREATE_TXG = ZPOOL_CONFIG_CREATE_TXG;
char *sZPOOL_CONFIG_TOP_GUID = ZPOOL_CONFIG_TOP_GUID;
char *sZPOOL_CONFIG_VDEV_TREE = ZPOOL_CONFIG_VDEV_TREE;
char *sZPOOL_CONFIG_TYPE = ZPOOL_CONFIG_TYPE;
char *sZPOOL_CONFIG_CHILDREN = ZPOOL_CONFIG_CHILDREN;
char *sZPOOL_CONFIG_ID = ZPOOL_CONFIG_ID;
char *sZPOOL_CONFIG_GUID = ZPOOL_CONFIG_GUID;
char *sZPOOL_CONFIG_PATH = ZPOOL_CONFIG_PATH;
char *sZPOOL_CONFIG_DEVID = ZPOOL_CONFIG_DEVID;
char *sZPOOL_CONFIG_METASLAB_ARRAY = ZPOOL_CONFIG_METASLAB_ARRAY;
char *sZPOOL_CONFIG_METASLAB_SHIFT = ZPOOL_CONFIG_METASLAB_SHIFT;
char *sZPOOL_CONFIG_ASHIFT = ZPOOL_CONFIG_ASHIFT;
char *sZPOOL_CONFIG_ASIZE = ZPOOL_CONFIG_ASIZE;
char *sZPOOL_CONFIG_DTL = ZPOOL_CONFIG_DTL;
char *sZPOOL_CONFIG_SCAN_STATS = ZPOOL_CONFIG_SCAN_STATS;
char *sZPOOL_CONFIG_VDEV_STATS = ZPOOL_CONFIG_VDEV_STATS;
char *sZPOOL_CONFIG_WHOLE_DISK = ZPOOL_CONFIG_WHOLE_DISK;
char *sZPOOL_CONFIG_ERRCOUNT = ZPOOL_CONFIG_ERRCOUNT;
char *sZPOOL_CONFIG_NOT_PRESENT = ZPOOL_CONFIG_NOT_PRESENT;
char *sZPOOL_CONFIG_SPARES = ZPOOL_CONFIG_SPARES;
char *sZPOOL_CONFIG_IS_SPARE = ZPOOL_CONFIG_IS_SPARE;
char *sZPOOL_CONFIG_NPARITY = ZPOOL_CONFIG_NPARITY;
char *sZPOOL_CONFIG_HOSTID = ZPOOL_CONFIG_HOSTID;
char *sZPOOL_CONFIG_HOSTNAME = ZPOOL_CONFIG_HOSTNAME;
char *sZPOOL_CONFIG_LOADED_TIME = ZPOOL_CONFIG_LOADED_TIME;
char *sZPOOL_CONFIG_UNSPARE = ZPOOL_CONFIG_UNSPARE;
char *sZPOOL_CONFIG_PHYS_PATH = ZPOOL_CONFIG_PHYS_PATH;
char *sZPOOL_CONFIG_IS_LOG = ZPOOL_CONFIG_IS_LOG;
char *sZPOOL_CONFIG_L2CACHE = ZPOOL_CONFIG_L2CACHE;
char *sZPOOL_CONFIG_HOLE_ARRAY = ZPOOL_CONFIG_HOLE_ARRAY;
char *sZPOOL_CONFIG_VDEV_CHILDREN = ZPOOL_CONFIG_VDEV_CHILDREN;
char *sZPOOL_CONFIG_IS_HOLE = ZPOOL_CONFIG_IS_HOLE;
char *sZPOOL_CONFIG_DDT_HISTOGRAM = ZPOOL_CONFIG_DDT_HISTOGRAM;
char *sZPOOL_CONFIG_DDT_OBJ_STATS = ZPOOL_CONFIG_DDT_OBJ_STATS;
char *sZPOOL_CONFIG_DDT_STATS = ZPOOL_CONFIG_DDT_STATS;
char *sZPOOL_CONFIG_SPLIT = ZPOOL_CONFIG_SPLIT;
char *sZPOOL_CONFIG_ORIG_GUID = ZPOOL_CONFIG_ORIG_GUID;
char *sZPOOL_CONFIG_SPLIT_GUID = ZPOOL_CONFIG_SPLIT_GUID;
char *sZPOOL_CONFIG_SPLIT_LIST = ZPOOL_CONFIG_SPLIT_LIST;
char *sZPOOL_CONFIG_REMOVING = ZPOOL_CONFIG_REMOVING;
char *sZPOOL_CONFIG_RESILVER_TXG = ZPOOL_CONFIG_RESILVER_TXG;
char *sZPOOL_CONFIG_COMMENT = ZPOOL_CONFIG_COMMENT;
char *sZPOOL_CONFIG_SUSPENDED = ZPOOL_CONFIG_SUSPENDED;
char *sZPOOL_CONFIG_TIMESTAMP = ZPOOL_CONFIG_TIMESTAMP;
char *sZPOOL_CONFIG_BOOTFS = ZPOOL_CONFIG_BOOTFS;
char *sZPOOL_CONFIG_MISSING_DEVICES = ZPOOL_CONFIG_MISSING_DEVICES;
char *sZPOOL_CONFIG_LOAD_INFO = ZPOOL_CONFIG_LOAD_INFO;
char *sZPOOL_CONFIG_REWIND_INFO = ZPOOL_CONFIG_REWIND_INFO;
char *sZPOOL_CONFIG_UNSUP_FEAT = ZPOOL_CONFIG_UNSUP_FEAT;
char *sZPOOL_CONFIG_ENABLED_FEAT = ZPOOL_CONFIG_ENABLED_FEAT;
char *sZPOOL_CONFIG_CAN_RDONLY = ZPOOL_CONFIG_CAN_RDONLY;
char *sZPOOL_CONFIG_FEATURES_FOR_READ = ZPOOL_CONFIG_FEATURES_FOR_READ;
char *sZPOOL_CONFIG_FEATURE_STATS = ZPOOL_CONFIG_FEATURE_STATS;
char *sZPOOL_CONFIG_ERRATA = ZPOOL_CONFIG_ERRATA;
char *sZPOOL_CONFIG_OFFLINE = ZPOOL_CONFIG_OFFLINE;
char *sZPOOL_CONFIG_FAULTED = ZPOOL_CONFIG_FAULTED;
char *sZPOOL_CONFIG_DEGRADED = ZPOOL_CONFIG_DEGRADED;
char *sZPOOL_CONFIG_REMOVED = ZPOOL_CONFIG_REMOVED;
char *sZPOOL_CONFIG_FRU = ZPOOL_CONFIG_FRU;
char *sZPOOL_CONFIG_AUX_STATE = ZPOOL_CONFIG_AUX_STATE;
char *sZPOOL_LOAD_POLICY = ZPOOL_LOAD_POLICY;
char *sZPOOL_LOAD_REWIND_POLICY = ZPOOL_LOAD_REWIND_POLICY;
char *sZPOOL_LOAD_REQUEST_TXG = ZPOOL_LOAD_REQUEST_TXG;
char *sZPOOL_LOAD_META_THRESH = ZPOOL_LOAD_META_THRESH;
char *sZPOOL_LOAD_DATA_THRESH = ZPOOL_LOAD_DATA_THRESH;
char *sZPOOL_CONFIG_LOAD_TIME = ZPOOL_CONFIG_LOAD_TIME;
char *sZPOOL_CONFIG_LOAD_DATA_ERRORS = ZPOOL_CONFIG_LOAD_DATA_ERRORS;
char *sZPOOL_CONFIG_REWIND_TIME = ZPOOL_CONFIG_REWIND_TIME;

static char _lasterr_[1024];

const char *lasterr(void) {
	return _lasterr_;
}

zpool_list_t *create_zpool_list_item() {
	zpool_list_t *zlist = malloc(sizeof(zpool_list_t));
	memset(zlist, 0, sizeof(zpool_list_t));
	return zlist;
}

int zpool_list_callb(zpool_handle_t *pool, void *data) {
	zpool_list_t **lroot = (zpool_list_t**)data;
	zpool_list_t *nroot = create_zpool_list_item();

	if ( !((*lroot)->zph) ) {
		(*lroot)->zph = pool;
	} else {
		nroot->zph = pool;
		nroot->pnext = (void*)*lroot;
		*lroot = nroot;
	}
	return 0;
}

zpool_list_ptr zpool_list_openall() {
	int err = 0;
	zpool_list_t *zlist = create_zpool_list_item();
	err = zpool_iter(libzfsHandle, zpool_list_callb, &zlist);
	if ( err != 0 || zlist->zph == NULL ) {
		zpool_list_free(zlist);
		zlist = NULL;
	}
	return zlist;
}

zpool_list_t* zpool_list_open(const char *name) {
	zpool_list_t *zlist = create_zpool_list_item();
	zlist->zph = zpool_open(libzfsHandle, name);
	if ( zlist->zph ) {
		return zlist;
	} else {
		zpool_list_free(zlist);
	}
	return 0;
}

zpool_list_t *zpool_next(zpool_list_t *pool) {
	return pool->pnext;
}

void zpool_list_free(zpool_list_t *list) {
	zpool_list_ptr next;
	while(list) {
		next = list->pnext;
		free(list);
		list = next;
	}
}

void zpool_list_close(zpool_list_t *pool) {
	zpool_close(pool->zph);
	zpool_list_free(pool);
}

property_list_t *next_property(property_list_t *list) {
	if (list != 0) {
		return list->pnext;
	}
	return list;
}


void zprop_source_tostr(char *dst, zprop_source_t source) {
	switch (source) {
	case ZPROP_SRC_NONE:
		strcpy(dst, "none");
		break;
	case ZPROP_SRC_TEMPORARY:
		strcpy(dst, "temporary");
		break;
	case ZPROP_SRC_LOCAL:
		strcpy(dst, "local");
		break;
	case ZPROP_SRC_INHERITED:
		strcpy(dst, "inherited");
		break;
	case ZPROP_SRC_RECEIVED:
		strcpy(dst, "received");
		break;
	default:
		strcpy(dst, "default");
		break;
	}
}


property_list_ptr read_zpool_property(zpool_list_ptr pool, int prop) {

	int r = 0;
	zprop_source_t source;
	property_list_ptr list = new_property_list();

	r = zpool_get_prop(pool->zph, prop,
		list->value, INT_MAX_VALUE, &source, B_TRUE);
	if (r == 0) {
		// strcpy(list->name, zpool_prop_to_name(prop));
		zprop_source_tostr(list->source, source);
	} else {
		free_properties(list);
		return NULL;
	}
	list->property = (int)prop;
	return list;
}

property_list_ptr read_append_zpool_property(zpool_list_ptr pool, property_list_ptr proot, zpool_prop_t prop) {
	int r = 0;
	property_list_t *newitem = NULL;

	newitem = read_zpool_property(pool, prop);
	if (newitem == NULL) {
		return proot;
	}
	// printf("p: %s %s %s\n", newitem->name, newitem->value, newitem->source);
	newitem->pnext = proot;
	proot = newitem;

	return proot;
}

property_list_t *read_zpool_properties(zpool_list_ptr pool) {
	// read pool name as first property
	property_list_t *root = NULL, *list = NULL;

	root = read_append_zpool_property(pool, root, ZPOOL_PROP_NAME);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_SIZE);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_CAPACITY);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_ALTROOT);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_HEALTH);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_GUID);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_VERSION);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_BOOTFS);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_DELEGATION);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_AUTOREPLACE);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_CACHEFILE);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_FAILUREMODE);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_LISTSNAPS);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_AUTOEXPAND);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_DEDUPDITTO);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_DEDUPRATIO);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_FREE);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_ALLOCATED);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_READONLY);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_ASHIFT);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_COMMENT);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_EXPANDSZ);
	root = read_append_zpool_property(pool, root, ZPOOL_PROP_FREEING);

	list = new_property_list();
	list->property = ZPOOL_NUM_PROPS;
	sprintf(list->value, "%d", ZPOOL_NUM_PROPS);
	list->pnext = root;
	zprop_source_tostr(list->source, ZPROP_SRC_NONE);
	root = list;

	// printf("Finished properties reading.\n");
	return root;
}

pool_state_t zpool_read_state(zpool_handle_t *zh) {
	return zpool_get_state(zh);
}


const char *gettext(const char *txt) {
	return txt;
}
/*
 * Add a property pair (name, string-value) into a property nvlist.
 */
// int
// add_prop_list(const char *propname, char *propval, nvlist_t **props,
// 	boolean_t poolprop) {
// 	zpool_prop_t prop = ZPROP_INVAL;
// 	zfs_prop_t fprop;
// 	nvlist_t *proplist;
// 	const char *normnm;
// 	char *strval;

// 	if (*props == NULL &&
// 	    nvlist_alloc(props, NV_UNIQUE_NAME, 0) != 0) {
// 		(void) snprintf(_lasterr_, 1024, "internal error: out of memory");
// 		return (1);
// 	}

// 	proplist = *props;

// 	if (poolprop) {
// 		const char *vname = zpool_prop_to_name(ZPOOL_PROP_VERSION);

// 		if ((prop = zpool_name_to_prop(propname)) == ZPROP_INVAL &&
// 		    !zpool_prop_feature(propname)) {
// 			(void) snprintf(_lasterr_, 1024, "property '%s' is "
// 			    "not a valid pool property", propname);
// 			return (2);
// 		}

// 		/*
// 		 * feature@ properties and version should not be specified
// 		 * at the same time.
// 		 */
// 		// if ((prop == ZPROP_INVAL && zpool_prop_feature(propname) &&
// 		//     nvlist_exists(proplist, vname)) ||
// 		//     (prop == ZPOOL_PROP_VERSION &&
// 		//     prop_list_contains_feature(proplist))) {
// 		// 	(void) fprintf(stderr, gettext("'feature@' and "
// 		// 	    "'version' properties cannot be specified "
// 		// 	    "together\n"));
// 		// 	return (2);
// 		// }


// 		if (zpool_prop_feature(propname))
// 			normnm = propname;
// 		else
// 			normnm = zpool_prop_to_name(prop);
// 	} else {
// 		if ((fprop = zfs_name_to_prop(propname)) != ZPROP_INVAL) {
// 			normnm = zfs_prop_to_name(fprop);
// 		} else {
// 			normnm = propname;
// 		}
// 	}

// 	if (nvlist_lookup_string(proplist, normnm, &strval) == 0 &&
// 	    prop != ZPOOL_PROP_CACHEFILE) {
// 		(void) snprintf(_lasterr_, 1024, "property '%s' "
// 		    "specified multiple times", propname);
// 		return (2);
// 	}

// 	if (nvlist_add_string(proplist, normnm, propval) != 0) {
// 		(void) snprintf(_lasterr_, 1024, "internal "
// 		    "error: out of memory\n");
// 		return (1);
// 	}

// 	return (0);
// }

nvlist_t** nvlist_alloc_array(int count) {
	return malloc(count*sizeof(nvlist_t*));
}

void nvlist_array_set(nvlist_t** a, int i, nvlist_t *item) {
	a[i] = item;
}

void nvlist_free_array(nvlist_t **a) {
	free(a);
}

nvlist_t *nvlist_array_at(nvlist_t **a, uint_t i) {
	return a[i];
}

int refresh_stats(zpool_list_t *pool)
{
	boolean_t missing;
	int err = zpool_refresh_stats(pool->zph, &missing);
	if ( err != 0 ) {
		return err;
	}
	if ( missing == B_TRUE ) {
		return -1;
	}
	return 0;
}

const char *get_vdev_type(nvlist_ptr nv) {
	const char *value = NULL;
	int r = nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &value);
	if(r != 0) {
		return NULL;
	}
	return value;
}

uint64_t get_vdev_guid(nvlist_ptr nv) {
	uint64_t value = 0;
	nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &value);
	return value;
}

const vdev_stat_ptr get_vdev_stats(nvlist_ptr nv) {
	vdev_stat_ptr vs = NULL;
	uint_t count;
	int r = nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_VDEV_STATS, (uint64_t**)&vs, &count);
	if(r != 0) {
		return NULL;
	}
	return vs;
}

pool_scan_stat_ptr get_vdev_scan_stats(nvlist_t *nv) {
	pool_scan_stat_ptr vds = NULL;
	uint_t c;
	int r = nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_SCAN_STATS, (uint64_t**)&vds, &c);
	if(r != 0) {
		return NULL;
	}
	return vds;
}

vdev_children_ptr get_vdev_children(nvlist_t *nv) {
	int r;
	vdev_children_ptr children = malloc(sizeof(vdev_children_t));
	memset(children, 0, sizeof(vdev_children_t));
	r = nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN, &(children->first), &(children->count));
	if (r != 0) {
		free(children);
		return NULL;
	}
	return children;
}

vdev_children_ptr get_vdev_spares(nvlist_t *nv) {
	int r;
	vdev_children_ptr children = malloc(sizeof(vdev_children_t));
	memset(children, 0, sizeof(vdev_children_t));
	r = nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_SPARES, &(children->first), &(children->count));
	if (r != 0) {
		free(children);
		return NULL;
	}
	return children;
}

vdev_children_ptr get_vdev_l2cache(nvlist_t *nv) {
	int r;
	vdev_children_ptr children = malloc(sizeof(vdev_children_t));
	memset(children, 0, sizeof(vdev_children_t));
	r = nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_L2CACHE, &(children->first), &(children->count));
	if (r != 0) {
		free(children);
		return NULL;
	}
	return children;
}

const char *get_vdev_path(nvlist_ptr nv) {
	const char *path = NULL;
	uint64_t notpresent = 0;
	int r = nvlist_lookup_uint64(nv, ZPOOL_CONFIG_NOT_PRESENT, &notpresent);
	if (r == 0 || notpresent != 0) {
		if (  0 != nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) ) {
			return NULL;
		}
	}
	return path;
}

uint64_t get_vdev_is_log(nvlist_ptr nv) {
	uint64_t islog = B_FALSE;
	nvlist_lookup_uint64(nv, ZPOOL_CONFIG_IS_LOG, &islog);
	return islog;
}


// return
uint64_t get_zpool_state(nvlist_ptr nv) {
	uint64_t state = 0;
	nvlist_lookup_uint64(nv, ZPOOL_CONFIG_POOL_STATE, &state);
	return state;
}

uint64_t get_zpool_guid(nvlist_ptr nv) {
	uint64_t guid = 0;
	nvlist_lookup_uint64(nv, ZPOOL_CONFIG_POOL_GUID, &guid);
	return guid;
}

const char *get_zpool_name(nvlist_ptr nv) {
	const char *name = NULL;
	if (0 != nvlist_lookup_string(nv, ZPOOL_CONFIG_POOL_NAME, &name)) {
		return NULL;
	}
	return name;
}

const char *get_zpool_comment(nvlist_ptr nv) {
	const char *comment = NULL;
	if (0 != nvlist_lookup_string(nv, ZPOOL_CONFIG_COMMENT, &comment)) {
		return NULL;
	}
	return comment;
}

nvlist_ptr get_zpool_vdev_tree(nvlist_ptr nv) {
	nvlist_ptr vdev_tree = NULL;
	if ( 0 != nvlist_lookup_nvlist(nv, ZPOOL_CONFIG_VDEV_TREE,	&vdev_tree) ) {
		return NULL;
	}
	return vdev_tree;
}


nvlist_ptr go_zpool_search_import(libzfs_handle_ptr zfsh, int paths, char **path, boolean_t do_scan) {
	importargs_t idata;
	memset(&idata, 0, sizeof(importargs_t));
	nvlist_ptr pools = NULL;
	idata.path = path;
	idata.paths = paths;
	// idata.scan = 0;

	tpool_t *t;
	t = tpool_create(1, 5 * sysconf(_SC_NPROCESSORS_ONLN), 0, NULL);
	if (t == NULL)
			return NULL;

	libpc_handle_t lpch = {
		.lpc_lib_handle = zfsh,
		.lpc_ops = &libzfs_config_ops,
		.lpc_printerr = B_TRUE
	};
	pools = zpool_search_import(&lpch, &idata);

	tpool_wait(t);
	tpool_destroy(t);
	return pools;
}


int do_zpool_clear(zpool_list_t *pool, const char *device, u_int32_t load_policy) {
	nvlist_t *policy = NULL;
	int ret = 0;
	if (nvlist_alloc(&policy, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_uint32(policy, ZPOOL_LOAD_POLICY, load_policy) != 0)
		return (1);

	if (zpool_clear(pool->zph, device, policy) != 0)
		ret = 1;

	nvlist_free(policy);

	return (ret);
}

void collect_zpool_leaves(zpool_handle_t *zhp, nvlist_t *nvroot, nvlist_t *nv){
	uint_t children = 0;
	nvlist_t **child;
	uint_t i;

	(void) nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    &child, &children);

	if (children == 0) {
		char *path = zpool_vdev_name(libzfsHandle, zhp, nvroot,
		    VDEV_NAME_PATH);

		if (strcmp(path, VDEV_TYPE_INDIRECT) != 0)
			fnvlist_add_boolean(nv, path);

		free(path);
		return;
	}

	for (i = 0; i < children; i++) {
		collect_zpool_leaves(zhp, child[i], nv);
	}
}