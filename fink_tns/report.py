# Copyright 2020 AstroLab Software
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
from fink_tns.utils import extract_radec
from fink_tns.utils import inst_units, filters_dict, instrument
from fink_tns.utils import reporting_group_id, at_type, discovery_data_source_id
from fink_tns.utils import reporter, remarks
import json
import requests
from collections import OrderedDict
from astropy.time import Time
import pandas as pd
import os

def generate_photometry(data):
    dd = {
        "obsdate": "{}".format(Time(data['jd'], format='jd').fits.replace("T", " ")),
        "flux": "{}".format(data['magpsf']),
        "flux_error": "{}".format(data['sigmapsf']),
        "limiting_flux": "{}".format(data['diffmaglim']),
        "flux_units": "{}".format(inst_units),
        "filter_value": "{}".format(filters_dict[data['fid']]),
        "instrument_value": "{}".format(instrument),
        "exptime": "30",
        "observer": "Robot",
        "comments": "Data provided by ZTF, classified by Fink"
    }

    return dd

def generate_non_detection(data):
    dd = {
        "obsdate": "{}".format(Time(data['jd'], format='jd').fits.replace("T", " ")),
        "limiting_flux": "{}".format(data['diffmaglim']),
        "flux_units": "{}".format(inst_units),
        "filter_value": "{}".format(filters_dict[data['fid']]),
        "instrument_value": "{}".format(instrument),
        "exptime": "30",
        "observer": "Robot",
        "comments": "Data provided by ZTF, classified by Fink"
    }

    return dd

def extract_discovery_photometry(data):
    """
    """
    tmp_pho = []
    tmp_upp = []

    # add candidate into photometry
    tmp_pho.append(generate_photometry(data['candidate']))

    # loop over prv_candidates, and add into photometry or non-det
    for alert in data['prv_candidates']:
        if alert['magpsf'] != None:
            tmp_pho.append(generate_photometry(alert))
        else:
            tmp_upp.append(generate_non_detection(alert))

    # Sort photometry and keep the first one
    tmp_pho = sorted(tmp_pho, key=lambda i: i['obsdate'])
    first_photometry = tmp_pho[0]

    # Extract the last non-detection
    date_init = first_photometry['obsdate']
    filt_init = first_photometry['filter_value']
    tmp_upp = sorted(tmp_upp, key=lambda i: i['obsdate'])

    # Note we extract the last non-detection for the same filter!
    tmp_upp = [i for i in tmp_upp if (i['obsdate'] <= date_init) & (i['filter_value'] == filt_init)]

    if len(tmp_upp) == 0:
        last_non_detection = {
            "archiveid": "0",
            "archival_remarks": "ZTF non-detection limits not available"
        }
    else:
        last_non_detection = tmp_upp[-1]

    return first_photometry, last_non_detection

def build_report(data, photometry, non_detection):
    """
    """
    radec = extract_radec(data)
    report = {
        "ra": {
            "value": radec['ra'],
            "error": radec['ra_err'] * 3600,
            "units": "arcsec"
        },
        "dec": {
            "value": radec['dec'],
            "error": radec['dec_err'] * 3600,
            "units": "arcsec"
        },
        "reporting_group_id": reporting_group_id,
        "discovery_data_source_id": discovery_data_source_id,
        "reporter": reporter,
        "discovery_datetime": photometry['obsdate'],
        "at_type": at_type,
        "internal_name": data['objectId'],
        "remarks": remarks.format(data['objectId']),
        "non_detection": non_detection,
        "photometry": {"photometry_group": {'0': photometry}}
    }

    return report

def save_logs_and_return_json_report(name: str, folder: str, ids: list, report: dict):
    """
    """
    os.makedirs(folder, exist_ok=True)

    # Save processed ids on disk
    pdf_ids = pd.DataFrame.from_dict({'id': ids})
    pdf_ids.to_csv('{}/{}.csv'.format(folder, name), index=False)

    # Save report on disk
    json_report = '{}/{}.json'.format(folder, name)
    with open(json_report, 'w') as outfile:
        json.dump(report, outfile)
    return json_report

def format_to_json(source):
    # change data to json format and return
    parsed = json.loads(source, object_pairs_hook=OrderedDict)
    result = json.dumps(parsed, indent=4)
    return result

def send_json_report(api_key, url, json_file_path, tns_marker):
    """ Function for sending json reports (AT or Classification)

    Parameters
    ----------
    api_key: str
        API key for TNS
    url: str
        URL for posting results
    json_file_path: str
        Path to the generated report to be posted
    tns_marker: str
        New marker to be inserted in the header (user-agent).
        See https://www.wis-tns.org/content/tns-newsfeed#comment-wrapper-23710
    """
    # url for sending json reports
    json_url = url + '/bulk-report'

    # read json data from file
    json_read = format_to_json(open(json_file_path).read())

    # construct list of (key,value) pairs
    json_data = [
        ('api_key', (None, api_key)),
        ('data', (None, json_read))
    ]

    # define header
    headers = {'User-Agent': tns_marker}

    # send json report using request module
    response = requests.post(json_url, files=json_data, headers=headers)

    return response
