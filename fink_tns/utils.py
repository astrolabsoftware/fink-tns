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
import json
import requests
from collections import OrderedDict
import numpy as np
import pandas as pd
import glob

def search_tns(api_key, oid):
    """
    """
    orddict = OrderedDict(
        [
            ("units", "deg"),
            ("objname", ""),
            ("internal_name", oid)
        ]

    )

    search_data = [
        ('api_key', (None, api_key)),
        ('data', (None, json.dumps(orddict)))
    ]

    response=requests.post(
        "https://wis-tns.weizmann.ac.il/api/get/search",
        files=search_data,
        timeout=(5, 10)
    )

    try:
        reply = response.json()["data"]["reply"]
    except KeyError as e:
        reply = []

    return reply

def retrieve_groupid(api_key, oid):
    """
    """
    reply = search_tns(api_key, oid)

    if reply != []:
        objname = reply[0]["objname"]
    else:
        return -999

    data = {
        "objname": objname,
    }

    # get object type
    json_data = [
        ('api_key', (None, api_key)),
        ('data', (None, json.dumps(data)))
    ]

    response = requests.post(
        "https://wis-tns.weizmann.ac.il/api/get/object",
        files=json_data
    )

    data = response.json()['data']

    return data['reply']['discovery_data_source']['groupid']

def extract_radec(data):
    """
    """
    ra = []
    dec = []

    ra.append(data['candidate']['ra'])
    for alert in data['prv_candidates']:
        ra.append(alert['ra'])
    ra = np.array(ra)

    dec.append(data['candidate']['dec'])
    for alert in data['prv_candidates']:
        dec.append(alert['dec'])
    dec = np.array(dec)

    mask = (ra != None) & (dec != None)
    return {
        'ra': np.mean(ra[mask]),
        'ra_err': np.std(ra[mask]),
        'dec': np.mean(dec[mask]),
        'dec_err': np.std(dec[mask])
    }

def read_past_ids(folder):
    """
    """
    pdf = pd.concat([pd.read_csv(i) for i in glob.glob('{}/*.csv'.format(folder))])
    return pdf
