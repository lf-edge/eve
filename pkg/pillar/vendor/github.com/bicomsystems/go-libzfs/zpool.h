/* C wrappers around some zfs calls and C in general that should simplify
 * using libzfs from go language, make go code shorter and more readable.
 */

#ifndef SERVERWARE_ZPOOL_H
#define SERVERWARE_ZPOOL_H

/* Rewind request information */
#define	ZPOOL_NO_REWIND		1  /* No policy - default behavior */
#define	ZPOOL_NEVER_REWIND	2  /* Do not search for best txg or rewind */
#define	ZPOOL_TRY_REWIND	4  /* Search for best txg, but do not rewind */
#define	ZPOOL_DO_REWIND		8  /* Rewind to best txg w/in deferred frees */
#define	ZPOOL_EXTREME_REWIND	16 /* Allow extreme measures to find best txg */
#define	ZPOOL_REWIND_MASK	28 /* All the possible rewind bits */
#define	ZPOOL_REWIND_POLICIES	31 /* All the possible policy bits */

struct zpool_list {
	zpool_handle_t *zph;
	void *pnext;
};

struct vdev_children {
	nvlist_t **first;
	uint_t count;
};

typedef struct zpool_list zpool_list_t;
typedef struct zpool_list* zpool_list_ptr;
typedef struct vdev_children vdev_children_t;
typedef struct vdev_children* vdev_children_ptr;

typedef struct pool_scan_stat* pool_scan_stat_ptr;

zpool_list_t *create_zpool_list_item();
void zprop_source_tostr(char *dst, zprop_source_t source);

zpool_list_t* zpool_list_open(const char *name);
zpool_list_ptr zpool_list_openall();
zpool_list_t *zpool_next(zpool_list_t *pool);

void zpool_list_free(zpool_list_t *list);
void zpool_list_close(zpool_list_t *pool);

property_list_ptr read_zpool_property(zpool_list_ptr pool, int prop);
property_list_t *read_zpool_properties(zpool_list_ptr pool);
property_list_t *next_property(property_list_t *list);

pool_state_t zpool_read_state(zpool_handle_t *zh);


const char *lasterr(void);

// int
// add_prop_list(const char *propname, char *propval, nvlist_t **props,
//     boolean_t poolprop);

nvlist_t** nvlist_alloc_array(int count);
void nvlist_array_set(nvlist_t** a, int i, nvlist_t *item);
void nvlist_free_array(nvlist_t **a);
nvlist_t *nvlist_array_at(nvlist_t **a, uint_t i);

int refresh_stats(zpool_list_t *pool);

const char *get_vdev_type(nvlist_ptr nv);
uint64_t get_vdev_guid(nvlist_ptr nv);
const vdev_stat_ptr get_vdev_stats(nvlist_ptr nv);
pool_scan_stat_ptr get_vdev_scan_stats(nvlist_t *nv);
vdev_children_ptr get_vdev_children(nvlist_t *nv);
vdev_children_ptr get_vdev_spares(nvlist_t *nv);
vdev_children_ptr get_vdev_l2cache(nvlist_t *nv);
const char *get_vdev_path(nvlist_ptr nv);
uint64_t get_vdev_is_log(nvlist_ptr nv);

uint64_t get_zpool_state(nvlist_ptr nv);
uint64_t get_zpool_guid(nvlist_ptr nv);
const char *get_zpool_name(nvlist_ptr nv);
const char *get_zpool_comment(nvlist_ptr nv);

nvlist_ptr get_zpool_vdev_tree(nvlist_ptr nv);

nvlist_ptr go_zpool_search_import(libzfs_handle_ptr zfsh, int paths, char **path, boolean_t do_scan);

uint64_t set_zpool_vdev_online(zpool_list_t *pool, const char *path, int flags);
int set_zpool_vdev_offline(zpool_list_t *pool, const char *path, boolean_t istmp, boolean_t force);
int do_zpool_clear(zpool_list_t *pool, const char *device, u_int32_t rewind_policy);
void collect_zpool_leaves(zpool_handle_t *zhp, nvlist_t *nvroot, nvlist_t *nv);


extern char *sZPOOL_CONFIG_VERSION;
extern char *sZPOOL_CONFIG_POOL_NAME;
extern char *sZPOOL_CONFIG_POOL_STATE;
extern char *sZPOOL_CONFIG_POOL_TXG;
extern char *sZPOOL_CONFIG_POOL_GUID;
extern char *sZPOOL_CONFIG_CREATE_TXG;
extern char *sZPOOL_CONFIG_TOP_GUID;
extern char *sZPOOL_CONFIG_VDEV_TREE;
extern char *sZPOOL_CONFIG_TYPE;
extern char *sZPOOL_CONFIG_CHILDREN;
extern char *sZPOOL_CONFIG_ID;
extern char *sZPOOL_CONFIG_GUID;
extern char *sZPOOL_CONFIG_PATH;
extern char *sZPOOL_CONFIG_DEVID;
extern char *sZPOOL_CONFIG_METASLAB_ARRAY;
extern char *sZPOOL_CONFIG_METASLAB_SHIFT;
extern char *sZPOOL_CONFIG_ASHIFT;
extern char *sZPOOL_CONFIG_ASIZE;
extern char *sZPOOL_CONFIG_DTL;
extern char *sZPOOL_CONFIG_SCAN_STATS;
extern char *sZPOOL_CONFIG_VDEV_STATS;
extern char *sZPOOL_CONFIG_WHOLE_DISK;
extern char *sZPOOL_CONFIG_ERRCOUNT;
extern char *sZPOOL_CONFIG_NOT_PRESENT;
extern char *sZPOOL_CONFIG_SPARES;
extern char *sZPOOL_CONFIG_IS_SPARE;
extern char *sZPOOL_CONFIG_NPARITY;
extern char *sZPOOL_CONFIG_HOSTID;
extern char *sZPOOL_CONFIG_HOSTNAME;
extern char *sZPOOL_CONFIG_LOADED_TIME;
extern char *sZPOOL_CONFIG_UNSPARE;
extern char *sZPOOL_CONFIG_PHYS_PATH;
extern char *sZPOOL_CONFIG_IS_LOG;
extern char *sZPOOL_CONFIG_L2CACHE;
extern char *sZPOOL_CONFIG_HOLE_ARRAY;
extern char *sZPOOL_CONFIG_VDEV_CHILDREN;
extern char *sZPOOL_CONFIG_IS_HOLE;
extern char *sZPOOL_CONFIG_DDT_HISTOGRAM;
extern char *sZPOOL_CONFIG_DDT_OBJ_STATS;
extern char *sZPOOL_CONFIG_DDT_STATS;
extern char *sZPOOL_CONFIG_SPLIT;
extern char *sZPOOL_CONFIG_ORIG_GUID;
extern char *sZPOOL_CONFIG_SPLIT_GUID;
extern char *sZPOOL_CONFIG_SPLIT_LIST;
extern char *sZPOOL_CONFIG_REMOVING;
extern char *sZPOOL_CONFIG_RESILVER_TXG;
extern char *sZPOOL_CONFIG_COMMENT;
extern char *sZPOOL_CONFIG_SUSPENDED;
extern char *sZPOOL_CONFIG_TIMESTAMP;
extern char *sZPOOL_CONFIG_BOOTFS;
extern char *sZPOOL_CONFIG_MISSING_DEVICES;
extern char *sZPOOL_CONFIG_LOAD_INFO;
extern char *sZPOOL_CONFIG_REWIND_INFO;
extern char *sZPOOL_CONFIG_UNSUP_FEAT;
extern char *sZPOOL_CONFIG_ENABLED_FEAT;
extern char *sZPOOL_CONFIG_CAN_RDONLY;
extern char *sZPOOL_CONFIG_FEATURES_FOR_READ;
extern char *sZPOOL_CONFIG_FEATURE_STATS;
extern char *sZPOOL_CONFIG_ERRATA;
extern char *sZPOOL_CONFIG_OFFLINE;
extern char *sZPOOL_CONFIG_FAULTED;
extern char *sZPOOL_CONFIG_DEGRADED;
extern char *sZPOOL_CONFIG_REMOVED;
extern char *sZPOOL_CONFIG_FRU;
extern char *sZPOOL_CONFIG_AUX_STATE;
extern char *sZPOOL_LOAD_POLICY;
extern char *sZPOOL_LOAD_REWIND_POLICY;
extern char *sZPOOL_LOAD_REQUEST_TXG;
extern char *sZPOOL_LOAD_META_THRESH;
extern char *sZPOOL_LOAD_DATA_THRESH;
extern char *sZPOOL_CONFIG_LOAD_TIME;
extern char *sZPOOL_CONFIG_LOAD_DATA_ERRORS;
extern char *sZPOOL_CONFIG_REWIND_TIME;


#endif
/* SERVERWARE_ZPOOL_H */
