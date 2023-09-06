# Persisted Cache (persistcache)

## Use-case

This package implements a persistance cache. The main use-case is to store data on filesystem and
provide access to it via API. Limitation of current implementation is that data should be represented
as string. This was developed for configuration services feature in EVE. Since there is an option for 
user to provide object to store via inline query, EVE has to store it even after reboot.

## API & Usage

Main structure is `pesistCache` outside of `persistcache` package it could be created via `Load` function:
it is loads values from cache if they are present or created folder if there was none.
`persistCache` structure has 3 operations:

- *Get* value from in-memory cache
- *Put* value to in-memory cache and store it in filesystem
- *Delete* value from in-memory cache and filesystem
- *Close* persistCache, should be used before freeing resource

Note that persistCache create lock file which does not allow using same folder in different threads, goroutines, apps, before creating instance on the same resource one should *Close* first instance. In case of multithreading use it is advised to use same object (basic mutex is implemented, so persistCache is not lock-free object, but you stil can share it between goroutines)

## Design decisions

### Why we are storing separate files and not saving whole structure as file?
+ If objects stored are large it takes less time to save/update them and less code
+ Access to cache file is easier

### Why store `string` and not `interface{}`
This way library user bears responsibility of marshalling and unmarshalling object on his side, keeping this
library simple
