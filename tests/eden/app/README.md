# Application state detector

The syntax for calling this detector is:

```console
eden.app.test [options] state app_name...
```

Where "status" is the standard state of the application (for example, RUNNING)
or "-" to detect deletion of applications.

Test specific "options":

* -timewait -- Timewait for waiting (1 min by default).

[E-script test for 2 dockers](testdata/2dockers_test.txt).
