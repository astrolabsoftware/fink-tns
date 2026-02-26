[![pypi](https://img.shields.io/pypi/v/fink-tns.svg)](https://pypi.python.org/pypi/fink-tns)
# Fink TNS

This repository hosts scripts to define a TNS bot to push extragalactic candidates from Fink to TNS. Usage:

```bash
# ZTF
$ python submit_from_api.py -h
usage: submit_from_api.py [-h] [-objectId OBJECTID] [-remarks REMARKS] [-reporter REPORTER] [-attype ATTYPE] [-outpath OUTPATH]

Submit a ZTF object from the Fink database to TNS

optional arguments:
  -h, --help          show this help message and exit
  -objectId OBJECTID  ZTF objectId
  -remarks REMARKS    Message to be displayed in the `Remarks` section on TNS
  -reporter REPORTER  Message to be displayed on the `Reporter/s` section on TNS
  -attype ATTYPE      AT type.
  -outpath OUTPATH    Path where credentials are stored.

# LSST
python submit_from_lsst_api.py -h
usage: submit_from_lsst_api.py [-h] [-diaObjectId DIAOBJECTID] [-remarks REMARKS] [-reporter REPORTER] [-attype ATTYPE]
                               [-outpath OUTPATH] [--dry_run]

Submit a LSST object from the Fink database to TNS

options:
  -h, --help            show this help message and exit
  -diaObjectId DIAOBJECTID
                        LSST objectId
  -remarks REMARKS      Message to be displayed in the `Remarks` section on TNS
  -reporter REPORTER    Message to be displayed on the `Reporter/s` section on TNS
  -attype ATTYPE        AT type.
  -outpath OUTPATH      Path where credentials are stored.
  --dry_run             If set, do not send the report to TNS (useful for inspection).
```

You need credentials to submit objects.
