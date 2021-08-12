# Volume state detector

The syntax for calling this detector is:

```console
eden.vol.test [options] state vol_name...
```

Where "status" is the standard state of the volume (for example, DELIVERED)
or "-" to detect deletion of volume.

Test specific "options":

* -timewait -- Timewait for waiting (1 min by default).

[E-script test for volumes](testdata/volumes_test.txt).
