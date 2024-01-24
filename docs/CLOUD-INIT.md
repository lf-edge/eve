# Cloud-Init

EVE supports [cloud-init](https://cloudinit.readthedocs.io/en/latest/) for configuring VMs and containers. The user-data is passed through the corresponding fields in the [AppInstanceConfig message](https://github.com/lf-edge/eve-api/tree/main/proto/config/appconfig.proto).

## Support in VMs

For VMs, EVE supports cloud-init configuration using the NoCloud datasource. With NoCloud, EVE manually provides both meta-data and user-data received from the controller to the VM. This is done by placing these files on a virtual CD-ROM in the form of an ISO image. Further EVE relies on the cloud-init system present in the ECO's VM image. Upon booting the VM instance, if a cloud-init installation is present, the system checks for these data files, and if found, processes the configurations or scripts defined in them.

For more information on the meta-data consult [ECO-METADATA.md](ECO-METADATA.md).

## Support in Containers

As opposed to the VM implementation, cloud-init in ECO containers does not rely on a cloud-init daemon being present in the container image. Instead, the cloud-init configuration is parsed by EVE and manually applied to the container. EVE's implementation supports two formats for user-data:

1. **Legacy Format (Available in all supported LTS versions):** This format only supports the definition of environment variables in the form of a simple key-value map. The equal sign "=" is used as delimiter. Example:

    ```text
    ENV1=value1
    ENV2=value2
    ```

2. **Original Cloud-Init Format (Available since EVE 11.3):** In this format, the user-data is specified like in any standard cloud-init configuration. The current EVE implementation only supports two user-data fields: `runcmd` and `write_files`.

   - `runcmd` is used to set environment variables, similar to the Legacy format. Note that the use of any command other than setting environment variables will result in an error. The env definitions must not be preceded by an `export` keyword, but its effect is implied in the implementation.

   - `write_files` field supports parameters such as path, content, permissions and encoding. It is used to write one or more files to the container image prior to the container start.

   Every cloud-init configuration must begin with the `#cloud-config` header. Example:

    ```yaml
    #cloud-config
    runcmd:
      - ENV1=value1
      - ENV2=value2
    write_files:
      - path: /etc/injected_file.txt
        permissions: '0644'
        encoding: b64
        content: YmxhYmxh
    ```

## Versioning

Both VM and container implementations support versioning of the user-data. This means that the cloud-init configuration is only reapplied if the version of the user-data has changed. The version is specified in the meta-data file in the `instance-id` field.

If the controller implementation does not support versioning, the user-data will be reapplied each time the version of the `AppInstanceConfig` changes.
