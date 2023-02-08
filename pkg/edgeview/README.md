# Edgeview container in EVE

## ./src directory

It contains the main package of golang source for 'eve-edgeview' container on EVE device. The 'edge-view-init.sh' script is started with the container and in a loop for start/stop the edgeview program base on the configurations. The same script is run on the client side, the environment variable `EDGEVIEW_CLIENT` needs to be set and passed in.

## ./dispatcher directory

It contains an example of golang source for 'edgeview' websocket dispatcher running in the cloud or in some VPN servers

## Dockerfiles

The 'Dockerfile' in the directory is used for EVE to build the 'edgeview' container running on EVE device
The same docker container `lfedge/eve-edgeview` can be run on user laptops.

## Query script

The 'query-edgeview.sh' is an example of running the `lfedge/eve-edgeview` docker container on the client computer

## Makefile

the 'Makefile' supports in pkg/edgeview directory:

(1) `make eve-edgeview` to build the `lfedge/eve-edgeview:latest` docker container;

(2) `make wss-server` to build a golang program for 'edgeview' websocket dispatcher. It needs to be run this compile on a Linux server if the websocket dispatcher will run in the same architecture;

## Help

On edge-view client container, or `lfedge/eve-edgeview` with environment variable EDGEVIEW_CLIENT=1, use '-h' or '-help' to see all the options, and one can do help on specific command option to get detail on the command.

```console
edge-view-query [ -token <session-token> ] [ -debug ] [ -inst <instance-id> ] <query string>
 options:
  log/search-pattern [ -time start_time-end_time -json -type app|dev -line num ]

  pub/ [baseosmgr domainmgr downloader global loguploader newlogd nim nodeagent tpmmgr vaultmgr volumemgr watcher zedagent zedclient zedmanager zedrouter zfsmanager]

  [acl app arp connectivity flow if mdns nslookup ping route socket speed tcp tcpdump trace url wireless]
  [app configitem cat cp datastore download du hw lastreboot ls model newlog pci ps cipher top usb volume]
```
