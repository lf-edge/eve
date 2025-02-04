/*
Package mu contains functions for marshalling go values to and unmarshalling them from the TPM wire format.

Go types are marshalled to and from the TPM wire format according to the following rules:

  - UINT8 <-> uint8

  - BYTE <-> byte

  - INT8 <-> int8

  - BOOL <-> bool

  - UINT16 <-> uint16

  - INT16 <-> int16

  - UINT32 <-> uint32

  - INT32 <-> int32

  - UINT64 <-> uint64

  - INT64 <-> int64

  - TPM2B prefixed types (sized buffers with a 2-byte size field) have 2 representations
    in go:

    1. []byte, or any type with an identical underlying type. A zero sized value is
    unmarshalled to nil.

    2. Pointer to a struct, either referenced from a field with the `tpm2:"sized"` tag
    or wrapped with the Sized() function. A zero sized value is represented as a nil pointer.

  - TPMA prefixed types (attributes) <-> whichever go type corresponds to the underlying TPM
    type (UINT8, UINT16, or UINT32).

  - TPM_ALG_ID (algorithm enum) <-> uint16

  - TPML prefixed types (lists with a 4-byte length field) <-> slice of whichever go type
    corresponds to the underlying TPM type. Zero length lists are unmarshalled to nil.

  - TPMS prefixed types (structures) <-> struct

  - TPMT prefixed types (tagged union) <-> struct with at least one member that is a struct
    or pointer to a struct that represents a union. The first member is the selector field
    unless overridden on the union member with the `tpm2:"selector:<field_name>"` tag.

  - TPMU prefixed types (unions) <-> struct which implements the Union interface. The default
    selector field can be overridden by using the `tpm2:"selector:<field_name>"` tag.

TPMI prefixed types (interface types) are generally not explicitly supported. These are used
by the TPM for type checking during unmarshalling, but this package doesn't distinguish between
TPMI prefixed types with the same underlying type.

Byte array types are supported and are marshalled to and from a fixed size bytes sequence.
No other array types are supported.

Pointers are automatically dererenced during marshalling and unmarshalling.

The marshalling code parses the "tpm2" tag on struct fields, the value of which is a comma
separated list of options. These options are:
  - sized1 - the field is a variable sized buffer with a single byte size field, used
    to support the TPMS_PCR_SELECT type. This is only valid for byte slice fields.
  - ignore - the field is ignored by this package.
  - selector:<field_name> - override the default selector field on a field to a structure
    that represents a union. The default behaviour without this option is to use the
    first field as the selector. It is invalid to use this on any field that isn't
    a structure or pointer to a structure that represents a union.
  - sized - turns a pointer to a structure into a sized (TPM2B) type. A zero sized
    structure is represented by a nil pointer. It is invalid to use this on any field
    that isn't a pointer to a structure.
  - raw - turns a slice into a raw type so that it is marshalled and unmarshalled without
    a size or length field. The slice must be pre-allocated to the correct length by the
    caller during unmarshalling. This is only valid for slice fields.
*/
package mu
