# Fink TNS

This repository hosts scripts to define a TNS bot to push early SN candidates from Fink. Usage:

```bash
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
```

You need credentials to submit objects.
