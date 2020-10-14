# EVE LOGGING PIPELINE

This document describes the different stages logs on a EVE edge node go through before being delivered to cloud. It also describes when and where log entries can be lost.

## Log Pipeline

The current log pipeline can be vertically split into the following three stages.

1. Log generation
2. Log aggregation and persistence
3. Log export to cloud

![EVE Logging Pipeline](pics/eve_logging_pipeline.png)

## Log Generation

All containers will now log directly to stdout, which are then picked up by containerd. Containerd then forwards the logs received to memlogd service that maintains a circular buffer of fixed size (5000 messages limit and 8192 bytes limit per message size) for storing log messages. Memlogd provides a way (via unix domain sockets) to read the logs present in it’s buffer and also stream the incoming logs.

The imemlogd plugin looks for json messages in the log and then skips the preceding bytes of log if found. This is done to make it possible for rsyslogd to parse the json message and extract fields from message and also add more fields to the existing message. Imemlogd plugin also puts a default tag name of the incoming container name into each of the log messages. For example logs sent to stdout from pillar container are tagged with "pillar.out" and those logs sent to stderr are tagged with "pillar.err" by default. Log messages that are successfully parsed by rsyslogd in json format will be modified to have some of the existing values changed and some new key-value pairs added.

Logs coming from pillar container that cannot be json parsed or truncated will have their source field set to pillar.out/pillar.err in EVE log API. It is at times useful to look for pillar.out/pillar.err as source match criteria in EVE log API. The same applies to other containers like lisp, xen-tools etc. Newlogd sorts out the application log messages and finds assigned application UUID and appName when writing into log files for applications.

Logs coming from xen-tools container are of three kinds:

* container itself logs under the name of ```xen-tools```
* xen hypervisor logs under the name ```hypervisor```
* each domain launched by xen-tools container also logs under the following names
  * ```guest_vm-[VM_NAME]``` logs the console output for VM_NAME domain
  * ```guest_vm_err-[VM_NAME]``` logs the console error ouptut for VM_NAME domain
  * ```qemu-dm-[VM_NAME]``` logs the qemu device model output
  * ```qdisk-[VM ID]``` logs the qdisk output

All logs from memlogd and from /dev/kmsg read by newlogd will be written to disk log file and then to be compressed into gzip log files. If the device crashes before 'newlogd' starts, the initial log messages is lost; When there is heavy disk usage or CPU load and newlogd does not get sufficient time to write incoming logs to disk, it can result in log loss from memlogd. Further investigation is needed to see if there is a way to inject a sequence number into the each log message inside the memlogd, such a sequence numbers would help detecting lost log messages.

The following diagram shows the flow of logs from containers to newlogd and to cloud.

![EVE Log Flow](pics/eve_newlog_flow.png)

## Log Aggregation, Reformating and Compression for Persistent Log Files

All logs collected from various containers/services/kernel in the system will reach newlogd deamon. Newlogd formats the log entries and writes into temporary log files(with temporary file name suffix, e.g. 12345678) on disk in /persist/newlog/collect directory. The logs from device host side will be saved to file with name prefix with 'dev.log.' (filename dev.log.12345678) and logs from application/guest side will be saved to files with name prefix with 'app.APP-UUID.log.' (file app.APP-UUID.log.12345678) where APP-UUID is the application UUID assigned to guest application. The temporary file is kept on the disk until either the file size has exceeded 400 KBytes or the elasped time on the file has been opened for longer than 5 minutes.

When the above log file is closed either due to size or time limit has reached, it will be moved and compressed with gzip protocol into either 'devUpload' or 'appUpload' directory. The size of the gzip file is limited to 50 KBytes due to the northbound queueing configuration. If the compressed file is larger than the limit, it will be split and compressed into two separate gzip files. The gzip filename is encoded with current timestamp in Unix seconds, such as 'dev.log.1600831551.gz' for device log, and with timestamp and application UUID such as 'app.62195aa9-7db4-4ac0-86d3-d8abe0ff0ea9.log.1599186248.gz' for application logs. The metadata such as device-UUID, the image partition, and image version or app Name for application are encoded as part of the gzip metadata header along with the gzip file.

Upon the device restart, any unfinished temporary log files of previous life left in /persist/newlog/collect directory will be first moved and compressed by newlogd deamon into their upload gzip directories before any current log events are written onto the disk.

If the device loses network connection to the controller, the accumulated gzip log files in the directories can not be uploaded and will continue to grow. There are two problems: 1) the disk space is limited and 2) once the connection is restored there will be too many log files to upload and most of the log information is not that useful due to long time losing the connection. The device will limit the log files for N hours post the network disconnection. For example it will keep for 10 hours of log information if the network connection is lost. The implementation can be a simple tail drop of logs after the 10 hours, or it can be to recycle the most recent 5 hours logs and leave the first 5 hours logs untouched. The device can also be in the condition of the network is reachable, but the upload is not fast enough the the disk space is almost full, for example only 100 M Bytes space left. The device will either start to tail drop the logs or the recycle the log files through portion o fthe existing log files as in the network disconnection case.

Once the gzip log files are uploaded to the cloud, any log entries in them will not be available on the device. For any log files are still waiting to be uploaded, they are in the '/persist/newlog/devUpload' and '/persist/newlog/appUpload' directories. EVE developers who have enabled ssh to the device for debugging purposes can look the log entries at in those directories by using "zcat" utility.

## Log export to cloud

"loguploader" is a pillar service which is responsible for uploading the gzip log files to the controller. The binary data of a gzip file is the payload portion of the authentication protobuf envolope structure. This is similar to all the other EVE POST messages, except that in those messsages the payload usually is data of another protobuf structure.

The upload is one gzip file at a time. The "loguploader" finds the earliest timestamp from the gzip file's filename and sends the data to the controller. If the upload is sucessful, then the uploaded gzip file is removed from the directory. If the upload encounters an error, it will come back to retry again. There can be several different failure cases:

1) the upload has no reply from the server and is TCP timed out
2) the upload gets http status code of 503 indicating that the controller is undergoing an update
3) the upload gets http status code of 4xx
4) the upload gets other types of error

For the case 1 and 2, "loguploader" will just come back to retry the same gzip file again (the earliest in timestamp). After it repeats this 3 times, the "uploader" will mark the controller as "unreachable". This "unreachable" status affects the disk space management by "newlogd" as mentioned above. For case 3, if it repeats continously for 10 times for the same gzip file, this gzip file will be moved into "/persist/newlog/failedUpload" directory, this is to prevent one bad file stops the other log files to be uploaded forever. There is no special action for case 4, the "loguploader" will come back to retry again later.

The uploading is controlled on a scheduled timer. When the timer fires, the "loguploader" checks both "devUpload" and "appUpload" directories, and picks file the earliest in timestamp of the gzip filename in the directory for uploading. The duration of the timer delay stays the same for 30 minutes, then it is recalculated. The current EVE implementaion calculates the timer delay based on these conditions:

* if the controller is in "unreachable" status, then the delay is set to a random in the range of 3 minutes to 15 minutes. This is mainly due to if the controller is out of reach for a while, many devices has many accumulated logs to be sent to the cloud, to space out the load in a longer duration will help the server side dealing with huge load in the initial startup stage.
* the device boots up, the timer value is set to 90 seconds (the first 30 minutes)
* the total number of gzip log files currently remains in the directories (the below timer value with 15% randomness):
  * 90 seconds if total file number is less than 5
  * 45 seconds if total file number is less than 25
  * 30 seconds if total file number is less than 50
  * 15 seconds if total file number is less than 200
  * 8 seconds if total file number is more than 200
* when the timer is recalculated with above criterion, one exception is that the new time delay will be allowed to go smaller or it will be kept the same as before if there exists more than 5 files in the directory. This is to prevent the total files in the directory oscillating around a high number which would cause a longer delay in uploading of gzip files.

The "loguploader" collects stats of round-trip delay, controller CPU load percentage and log batch processing time. The current EVE implementation does not use those stats in calculating the uploading timer values.

To prevent the log messages grow without bounds over time, the 'failedUpload' directory will only keep up to 1000 gzip files, each with maximum of 50K, to be under 50M in the directory. The '/persist' partition space is monitored, and if the available space is under 100M, the 'newlogd' will kick in the gzip file recycle operation just as the controller uplink is unreachable.

## Log files still present in device

Reboot reason and reboot stack files present in /persist and /persist/log directories. reboot-reaon, reboot-stack files present in /persist/log directory get appended with updates. The sames files in /persist directory keep getting overwritten with new content every time there is USR1 signal sent to a process or in the event of Fatal crash. These stack traces are also exported to cloud using logging mechanism.

## Object life cycle events and relations

Objects in EVE software can transition through many different states. These state transitions can be easily logged/tracked using object logging infrastructure that we have.
Look at ```pkg/pillar/base/logobjecttypes.go``` for reference.

Life cycle events can be logged automatically for objects that implement ```base.LoggableObject``` interface.
There are hooks added into pubsub that call logging functions for objects that implement the following methods.

* ```LogKey()```    -> Key using which the object can be identified uniquely
* ```LogCreate()``` -> Called when a new instance of the object is created in the view of pubsub.
* ```LogModify()``` -> Called when the object gets modified and published to pubsub.
* ```LogDelete()``` -> Called when the object is unpublished from pubsub.

Every time a object gets added to pubsub or gets modified log events are automatically generated. This helps in tracing through the state
transitions that the object goes through while traversing between different EVE services.

Reference implementation can be seen for AppInstanceConfig, AppInstanceStatus objects present in ```pkg/pillar/types/zedmanagertypes.go```.

Similarly relations between objects can be represented/logged using relation type objects with this infrastructure.
Same relation implementation between AppInstanceConfig and VolumeConfig can be found in functions AddOrRefcountVolumeConfig, MaybeRemoveVolumeConfig.

### Precautions with naming new keys in Log objects

1) Try and use exiting key values used in other object types before creating new keys.
2) If it becomes mandatory to create a new key field, suffix the key name with the type of value. We currently only support ```-int64``` & ```-bool```
suffixes for keys. Anything else shall be treated as text/string type by cloud software.

# Helpful debug commands

1. If you are debugging a device and would like to read/tail logs directly from memlogd buffers, use the following command.

```/hostfs/usr/bin/logread -F -socket /run/memlogdq.sock```.
This command starts by dumping all logs present in the current circular buffers and acts like tail command after that (dump to screen as and when a new log comes into memlogd).
