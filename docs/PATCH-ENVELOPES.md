# Patch Envelopes

## What is Patch Envelope?

Patch Envelope is a functionality in EVE that helps you change data in your App Instance in
runtime without the need to reboot instance, or recreate image. Imagine that in order to change
configuration in one of your program, you have to create new OS image and flush it to your computer.
With Patch Envelope you don’t have to do that. Patch Envelope constitutes of Binary Artefacts (blobs)
which are base64-encoded objects. This can be anything, from binary file to a configuration yaml file.
Those Patch Envelopes are exposed to App Instance via Metadata [server](./ECO-METADATA.md).

## Why should I use it?

When recreating image doesn’t make sense (i.e. you just want to change one configuration parameter and
you don’t want to recreate VM image) or when downtime is not an option for you

## How can I use it?

In EVE every App Instance connected to local network instances is exposed to Metadata server at
`169.254.169.254`. It has bunch of useful endpoints, amongst them are patch envelope endpoints. So within
App Instance one can access Patch Envelopes available to specific App Instance by getting description.json.
This would return list of Patch Envelopes available to this App Instance.

```bash
curl -X GET -v http://169.254.169.254/eve/v1/patch/description.json
[

    {
        "PatchId":"699fbdb2-e455-448f-84f5-68e547ec1305",
        "Version":"1",
        "BinaryBlobs":[
            {
                "file-name":"textfile1.txt",
                "file-sha":"%FILE_SHA",
                "file-meta-data":"YXJ0aWZhY3QgbWV0YWRhdGE=",
                "url":"http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile1.txt"
            },
            {
                "file-name":"textfile2.txt",
                "file-sha":"%FILE_SHA%",
                "file-meta-data":"YXJ0aWZhY3QgbWV0YWRhdGE=",
                "url":"http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile2.txt"
            }
        ],
        "VolumeRefs":null
    }

]
```

Every Patch Envelope contains of one or more Binary Artefacts (Blobs) which are base64-encoded objects.
Each object can be downloaded by calling URL, i.e.

```bash
curl -X GET http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile1.txt
```

will get you base64-encoded file.Note that you can download zip archive of all binary artifacts for a
given patch envelope by calling

```bash
curl -X GET http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305 > a.zip
```

Flow diagram of the process is below

![process-flow](./images/eve-pe-process-flow.png)

Full OpenAPI (Swagger) specification for patch envelope endpoint can be found [here](./api/patch-envelopes.yml).
You can generate client from this specification and use it to develop your application.

## What types of Binary Artifacts are there?

There’re two types of Binary Artifacts (Blobs): inline and external.
There is no distinction in the API between internal and external artifacts from the application perspective.
However, there’s a difference on how this artifacts are treated in EVE. Inline binary
artifacts are small size artifacts (max 10KBytes) which are part of EdgeDevConfig,
whereas external patch envelopes are represented as Volumes which are handled
by [volumemgr](../pkg/pillar/docs/volumemgr.md).

## Where Binary Artifacts are stored?

Inline Artifacts are stored as part of EdgeDevConfig. External artifacts are
stored in datastorage specified. EVE downloads artifacts directly from datastorage.
Keep this in mind configuring ACLs and access.

## How does it work?

![patch-flow](./images/eve-pe-patch-flow.png)

Internally, Metadata Server stores envelopes which come from EdgeDevConfig parsed
by zedagent. Binary Artifacts can be of two different types: inline and external.
Metadata server stores VolRef – volume references, which are changed to BinaryBlobs
once volumes are downloaded. Note that this process is async and it might take time.
All communication in this process is done via PubSub. When AppInstance downloads inline
object it’s served from Metadata server (zedrouter microservice). In case of external
patch envelopes – Metadata serves file from volume. For more information on how it works
in code refer [here](https://github.com/lf-edge/eve/blob/0a8b21ec5de3bf6a2613c2c6f2e2af7e353b1e98/pkg/pillar/cmd/zedrouter/patchenvelopes.go#L18C1-L47C88)
