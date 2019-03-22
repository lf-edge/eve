The following variables can be set using zcli on a per-project basis using e.g.,
    zcli project update <name> [--config=<key:value>...]
or on a per asset basis using
   zcli device update <name> [--config=<key:value>...]
For example,
zcli device update sc-supermicro-zc2 --config=debug.enable.ssh:true

app.allow.vnc	   boolean - allow access to the app using the VNC port
		   	     tcp port

timer.config.interval	integer in seconds - how frequently device gets config
timer.metric.interval	integer in seconds - how frequently device reports metrics
timer.reboot.no.network	integer in seconds - reboot after no cloud connectivity
timer.update.fallback.no.network integer in seconds - fallback after no cloud connectivity
timer.test.baseimage.update	integer in seconds - commit to update
timer.use.config.checkpoint	integer in seconds - use checkpointed config if no cloud connectivity
timer.gc.download		integer in seconds - garbage collect unused downloaded objects
timer.gc.vdisk			integer in seconds - garbage collect unused virtual disk
timer.download.retry		integer in seconds - retry a failed download
timer.boot.retry		integer in seconds - retry a failed domain boot
timer.port.georedo		default 3600 seconds - redo IP geolocation
timer.port.georetry		default 600 seconds - retry geolocation after failure
timer.port.testduration		default 30 - wait for DHCP to give address
timer.port.testinterval		default 300 seconds - retest the current port config
timer.port.testbetterinterval	default 0 seconds (disabled) - test a higher prio port config
network.fallback.any.eth	"enabled" or "disabled" - default enabled - if no connectivity try any Eth

debug.enable.usb		boolean - default true on device
debug.enable.ssh		boolean - default true on device
debug.default.loglevel		string - default "info"
debug.default.remote.loglevel	string - default "info" TBD change to "warn"?

In addition, for each agentname, there are specific overrides for the default
ones with the names:
debug.<agentname>.loglevel		string - if set overrides debug.default.loglevel
debug.<agentname>.remote.loglevel	string - overrides debug.default.remote.loglevel
