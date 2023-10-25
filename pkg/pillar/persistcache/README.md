# Persisted Cache (persistcache)

## Use-case

This package implements a persistence cache. The main use-case is to store data on filesystem and
provide access to it via API. Limitation of current implementation is that data should be represented
as string. This was developed for patch envelope feature in [EVE](https://github.com/lf-edge/eve/blob/master/docs/PATCH-ENVELOPES.md). Since there is an option for
user to provide object to store via inline query, EVE has to store it even after reboot.

From library user perspective this library works as `map[string]string` with respective files created for each key in root folder.

## API & Usage

Create `persistCache` structure by calling `New`

```golang
rootFilePath := "/my/root/file/path"
pc := persistcache.New(rootFilePath)
```

In case there are any objects (files) in specified `rootFilePath`, they will lazily initialized,
that means, they will actually be loaded only when `Get` function is called

Add objects to store by calling `Put`

```golang
pc.Put("myValidKey", []byte("myValidValue"))
```

check `isValidKey` and `isValidValue` to see limitations on valid keys and values.
Objects will be stored both in-memory and on filesystem.

Retrieve objects by calling `Get`

```golang
pc.Get("myValidKey")
```

Remove object from filesystem and from in-memory cache by calling `Delete`

```golang
pc.Delete("myValidKey")
```

## Design decisions

### Why we are storing separate files and not saving whole structure as file?

+ If objects stored are large it takes less time to save/update them and less code
+ Access to cache file is easier
+ Avoids a Put of one key from affecting the storage of another key, which could happen if it is a single file and the device is powered off before everything has been sync'ed to disk.

### Why store `[]byte` and not `interface{}` or `string`

This way library user bears responsibility of marshalling and unmarshalling object on its side, keeping persistcache library simple. In case of `string` it would imply a valid UTF-8 which is not required for `[]byte`.
