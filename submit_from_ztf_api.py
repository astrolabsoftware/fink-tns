#!/usr/bin/env python
# Copyright 2022-2023 AstroLab Software
# Author: Julien Peloton
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import requests
import pandas as pd
import io
import argparse

from fink_tns.report import extract_discovery_photometry_api
from fink_tns.report import build_report_api
from fink_tns.report import save_logs_and_return_json_report
from fink_tns.report import send_json_report

def main():
    """ Submit discovery to TNS
    """
    parser = argparse.ArgumentParser(description="Submit a ZTF object from the Fink database to TNS")
    parser.add_argument(
        '-objectId', type=str, default=None,
        help="ZTF objectId")
    parser.add_argument(
        '-remarks', type=str, default=None,
        help="Message to be displayed in the `Remarks` section on TNS")
    parser.add_argument(
        '-reporter', type=str, default=None,
        help="Message to be displayed on the `Reporter/s` section on TNS")
    parser.add_argument(
        '-attype', type=int, default=0,
        help="AT type.")
    parser.add_argument(
        '-outpath', type=str, default='./',
        help="Path where credentials are stored.")
    args = parser.parse_args(None)

    if args.objectId is None:
        raise NotImplementedError("You need to provide a ZTF objectId")
    if args.remarks is None:
        raise NotImplementedError("You need to provide the option remarks")
    if args.reporter is None:
        raise NotImplementedError("You need to provide a reporter")

    with open('{}/tns_marker.txt'.format(args.outpath)) as f:
        tns_marker = f.read().replace('\n', '')

    url_tns_api = "https://www.wis-tns.org/api"
    with open('{}/tns_api.key'.format(args.outpath)) as f:
        key = f.read().replace('\n', '')

    objects = [args.objectId]
    ids = []
    report = {"at_report": {}}
    for index, obj in enumerate(objects):
        r = requests.post(
            'https://api.fink-portal.org/api/v1/objects',
            json={
            'objectId': obj,
            'withupperlim': 'True'
            }
        )

        # Format output in a DataFrame
        pdf = pd.read_json(io.BytesIO(r.content))

        photometry, non_detection = extract_discovery_photometry_api(pdf)
        report['at_report']["{}".format(index)] = build_report_api(
            pdf,
            photometry,
            non_detection,
            remarks_custom=args.remarks,
            at_type_=args.attype,
            reporter_custom=args.reporter
        )
        ids.append(pdf['i:objectId'].values[0])

    json_report = save_logs_and_return_json_report(
        name=args.objectId,
        folder=args.outpath,
        ids=ids,
        report=report
    )
    print(report)

    r = send_json_report(key, url_tns_api, json_report, tns_marker)
    print(r.json())

if __name__ == "__main__":
    main()
