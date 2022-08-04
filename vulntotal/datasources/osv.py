#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import logging
from typing import Iterable
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class OSVDataSource(DataSource):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/google/osv/blob/master/LICENSE"
    url = "https://api.osv.dev/v1/query"

    def fetch_advisory(self, payload):
        response = requests.post(self.url, data=str(payload))
        if not response.status_code == 200:
            logger.error(f"Error while fetching {payload}: {response.status_code}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        payload = generate_payload(purl)
        if not payload:
            return
        advisory = self.fetch_advisory(payload)
        self._raw_dump.append(advisory)
        return parse_advisory(advisory)

    @classmethod
    def supported_ecosystem(cls):
        # source https://ossf.github.io/osv-schema/
        return {
        "npm": "npm", 
        "maven": "Maven", 
        "go": "Go", 
        "nuget": "NuGet", 
        "pypi": "PyPI", 
        "rubygems": "RubyGems", 
        "crates.io": "crates.io", 
        "packagist": "Packagist", 
        "linux": "Linux", 
        "oss-fuzz": "OSS-Fuzz", 
        "debian": "Debian", 
        "hex": "Hex", 
        "android": "Android", 
    }


def parse_advisory(response) -> Iterable[VendorData]:
    if "vulns" in response:
        for vuln in response["vulns"]:
            aliases = []
            affected_versions = []
            fixed = []

            if "aliases" in vuln:
                aliases.extend(vuln["aliases"])

            if "id" in vuln:
                aliases.append(vuln["id"])

            if "affected" in vuln:
                if "versions" in vuln["affected"][0]:
                    affected_versions.extend(vuln["affected"][0]["versions"])

                if vuln["affected"] and "ranges" in vuln["affected"][0]:
                    if "events" in vuln["affected"][0]["ranges"][0]:

                        events = vuln["affected"][0]["ranges"][0]["events"]
                        if events:
                            for event in events:
                                if "introduced" in event:
                                    affected_versions.append(event["introduced"])
                                if "fixed" in event:
                                    fixed.append(event["fixed"])
            yield VendorData(
                aliases=sorted(list(set(aliases))),
                affected_versions=sorted(list(set(affected_versions))),
                fixed_versions=sorted(list(set(fixed))),
            )

def get_closest_nuget_package_name(query):
    url_nuget_service = "https://api.nuget.org/v3/index.json"
    url_nuget_search = ""

    api_resources = requests.get(url_nuget_service).json()
    if "resources" in api_resources:
        for resource in api_resources["resources"]:
            if "@type" in resource and resource["@type"] == "SearchQueryService":
                url_nuget_search = resource["@id"]
                break

    if url_nuget_search:
        url_query = urljoin(url_nuget_search,f"?q={query}")
        query_response = requests.get(url_query).json()
        if "data" in query_response and query_response["data"]:
            return query_response["data"][0]["id"]


def generate_payload(purl):
    
    supported_ecosystem = OSVDataSource.supported_ecosystem()
    payload = {}
    payload["version"] = purl.version
    payload["package"] = {}
    
    if purl.type in supported_ecosystem:
        payload["package"]["ecosystem"] = supported_ecosystem[purl.type]

    if purl.type == "maven":
        if not purl.namespace:
            logger.error(f"Invalid Maven PURL {str(purl)}")
            return
        payload["package"]["name"] = f"{purl.namespace}:{purl.name}" 

    elif purl.type == "packagist":
        if not purl.namespace:
            logger.error(f"Invalid Packagist PURL {str(purl)}")
            return
        payload["package"]["name"] = f"{purl.namespace}/{purl.name}" 

    elif purl.type == "linux":
        if purl.name not in ("kernel", "Kernel"):
            logger.error(f"Invalid Linux PURL {str(purl)}")
            return
        payload["package"]["name"] = "Kernel"

    elif purl.type == "nuget":
        nuget_package = get_closest_nuget_package_name(purl.name)
        if not nuget_package:
            logger.error(f"Invalid NuGet PURL {str(purl)}")
            return
        payload["package"]["name"] = nuget_package

    elif purl.type == 'go' and purl.namespace:
            payload["package"]["name"] = f"{purl.namespace}/{purl.name}"

    else:
         payload["package"]["name"] = purl.name

    return payload
