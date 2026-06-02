[![pypi](https://img.shields.io/pypi/v/fink-tns.svg)](https://pypi.python.org/pypi/fink-tns)
# Fink TNS

This repository hosts scripts to define a TNS bot to push extragalactic candidates from Fink to TNS. Usage:

```bash
# ZTF
$ python submit_from_ztf_api.py -h

# LSST
python submit_from_lsst_api.py -h
```

You need credentials to submit objects.

## LSST submission example

### Set up credentials

Create a folder `credentials` at the root of the repository:

```bash
mkdir credentials
```

Put you credentials inside:

```bash
ls credentials/
-rw-r--r-- 1 fink  56 Jun  2 09:36 tns_marker.txt
-rw-r--r-- 1 fink  41 Jun  2 09:35 tns_api.key
```

### Build report and check

Specify the source ID, and some metadata, and run the script with the argument `--dry-run`:

```bash
#!/bin/bash

# LSST diaObjectId
OID="170296772058939493"

# Any remarks to be reported
REMARKS="Whatever is useful to say"

# Who is reporting, comma separated
REPORTER="YOUR NAMES, on behalf of the Fink Collaboration"

# 0 is Other, 1 is PSN, 2 is PNV, 3 is AGN, 4 is NUC, 6 is FRB
ATTYPE=1

# Path to credentials
OUTPATH="credentials"

python submit_from_lsst_api.py \
    -diaObjectId "$OID" \
    -remarks "$REMARKS" \
    -reporter "$REPORTER" \
    -attype "$ATTYPE" \
    -outpath "$OUTPATH" \
    --dry_run  # Only show the report without sending
```

You will get the report printed on screen:

```json
{'at_report': {'0': {'ra': {'value': 150.43671674454322, 'error': 0.06033093561674197, 'units': 'arcsec'}, 'dec': ...
```

Inspect carefully the values. If you are happy with, validate this report using the sandbox option:

```bash
python submit_from_lsst_api.py \
    -diaObjectId "$OID" \
    -remarks "$REMARKS" \
    -reporter "$REPORTER" \
    -attype "$ATTYPE" \
    -outpath "$OUTPATH" \
    --sandbox  # Send to the sandbox
```

If you get:

```json
{'id_code': 401, 'id_message': 'Unauthorized'}
```

You are likely using a wrong API key and/or marker. If all good, you should see:

```json
{'id_code': 200, 'id_message': 'OK', 'data': {'report_id': 277675}}
```

Connect to the sandbox website to confirm your transient is there:

1. go to https://sandbox.wis-tns.org, and connect
2. submit your coordinates
3. check your report appears at the bottom

## Final submission

If all  above is right (or if you are using a stable release of fink-tns), just submit your report:

```bash
python submit_from_lsst_api.py \
    -diaObjectId "$OID" \
    -remarks "$REMARKS" \
    -reporter "$REPORTER" \
    -attype "$ATTYPE" \
    -outpath "$OUTPATH"
```

Connect to the sandbox website to confirm your transient is there:

1. go to https://wwww.wis-tns.org, and connect
2. submit your coordinates
3. check your report appears at the bottom

