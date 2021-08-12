# Log/Info/Metric detector

The syntax for calling this detector is:

```console
eden.lim.test [options]
```

Test specific "options":

* -number -- The number of items (0=unlimited) you need to get (1 by default)
* -out -- Parameters for searching in out separated by ':'
* -timewait -- Timewait for waiting (10 min by default)

Testscripts:

* [E-script test for logs](testdata/log_test.txt)
* [E-script test for infos](testdata/info_test.txt)
* [E-script test for metrics](testdata/metric_test.txt)
