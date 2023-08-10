# Alpine Security Fix Tracker

This is a Flask web application which tracks security fixes in Alpine.

By using the Alpine secdb, we can generally deduce which CVEs have and have
not been fixed.  Some extensions to the secfixes reporting schema will be added
to allow package maintainers to denote false positives.

In the near future, state changes will be reported to a security announcement
list as the engine processes them.

## Setting up

You should create a virtualenv in the usual way, then do `pip3 install -r requirements.txt`.

If you want to use a database other than sqlite, you will want to install the driver for that,
for example `pip3 install psycopg2`.

Finally, you will want to write a config file: copy the example one and modify it to suit
your needs.

You will need to then set these env variables to something useful:

* `SECFIXES_TRACKER_CONFIG`: path to the config file
* `FLASK_APP`: the name of the app, `secfixes_tracker`

Once done, initialize the database with `flask init-db`.

## Tasks

Once the environment is configured, you can run various tasks:

### `flask run`

Runs the webserver.  This can also be done with gunicorn or something like that,
but that's not covered here.

### `flask init-db`

Initializes the database.

### `flask import-apkindex [repo]`

Imports the configured repositories.

### `flask import-secfixes [repo]`

Imports the configured secdb feeds.

### `flask import-nvd [feed-name]`

Imports an NVD feed, such as `2021` or `recent`.

Once the yearly feeds have been imported, you only need to import the `recent` feed
on a daily basis.

### `flask update-states [repo]`

Updates the various `VulnerabilityState` items based on the current contents of
the secfixes, NVD and apkindex feeds.  This should be run after the above import
tasks on an hourly basis.

## CPE rewriters

The config allows defining a set of custom rewriters.  These rewriters should be
defined as `lambda` functions which take a source package name as input.  They are
matched as either `cpe_vendor:source_pkgname` or `cpe_vendor:*` as a catch all.

For example:

```
CUSTOM_REWRITERS = {
    'jenkins:*': lambda x: 'jenkins',
}
```

Will define a rewriter which matches any package published by the 'jenkins' CPE
vendor and outputs 'jenkins' (as all jenkins components are in the `jenkins` source
package in Alpine).

## Cron

You'll want to run the import tasks, and then the update-states tasks.  That's all
that needs to be done.

## E-mail

The e-mail stuff is being redesigned to fit better into how the tracking engine was
implemented.  Watch this space once the e-mail stuff is ready for setup instructions.

## Caveats

At present, the database schema is unstable.  You will need to rebuild your database
when upgrading this software.  Once we hit version 1.0, the database schema will
be stable.
