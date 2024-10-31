import urllib3
import json
import logging
import gzip
import shutil
import os
import csv
from collections import defaultdict


def vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority):
    nextPage = True
    page = ""

    while nextPage:
        RED = "\033[91m"
        RESET = "\033[0m"

        LOG.info("Getting Vuln->Findings->Runtime..")
        url = f"https://{arg_secure_url_authority}/api/scanning/runtime/v2/workflows/results?cursor={page}&filter&limit=100&order=desc&sort=runningVulnsBySev&zones"
        response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        json_response_data = json.loads(response.data.decode())
        LOG.debug(f"Response status: {response.status}")
 
        # Check if there is a next page and if not exit the loop
        page = json_response_data.get("page", {}).get("next", "")
        if not page:
            nextPage = False
 
        # Initialize matches and vuln_counts
        matches = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))))
        vuln_counts = defaultdict(lambda: defaultdict(int))

        # Loop through all results
        for result in json_response_data["data"]:
            severityCount = 0
            foundInReport = False

            resultId = result["resultId"]
            resourceId = result["resourceId"]

            try:
                resultClusterName = result["recordDetails"]["labels"]["kubernetes.cluster.name"]
                resultNamespaceName = result["recordDetails"]["labels"]["kubernetes.namespace.name"]
                resultContainerName = result["recordDetails"]["labels"]["kubernetes.pod.container.name"]
                resultWorkloadType = result["recordDetails"]["labels"]["kubernetes.workload.type"]
                resultWorkloadName = result["recordDetails"]["labels"]["kubernetes.workload.name"]
            except KeyError as e:
                LOG.error(f"Missing key in result: {e}")
                LOG.error(f"Details of missing key: {result}")
                break
            
            # Check for image in the report and skip downloading the SBOM if its not there to save time
            with open('report', 'r') as file:
                for line in file:
                    if resourceId in line:
                        foundInReport = True

            if(foundInReport):
                LOG.info(f"Getting SBOM for resultId: {resultId}, resourceId: {resourceId}")
                url = f"https://{arg_secure_url_authority}/secure/vulnerability/v1beta1/sboms?assetId={resourceId}&assetType=container-image"
                response = http_client.request(method="GET", url=url, redirect=True, timeout=3)

                LOG.debug(f"Response status: {response.status}")

                if response.status != 200:
                    LOG.error(f"Error: {response.status} when trying to download SBOM {url}")
                    break
 
                json_response_data = json.loads(response.data.decode()) 

                # Extract the parameters name & version
                components = json_response_data["components"]

                for component in components:
                    name = component["name"]
                    version = component["version"]
                    group = component.get("group", {})  

                    #For java and others concat group and name from SBOM to match report format
                    if(group):
                        name = f"{group}:{name}"

                    # Open the file report which is CSV delimited
                    with open('report', mode='r') as file:
                        csv_reader = csv.DictReader(file)
                        
                        # Iterate through each row in the CSV
                        for row in csv_reader:
                            # Match the fields
                            if (row['Image ID'] == resourceId and
                                row['Package name'] == name and
                                row['Package version'] == version and
                                row['K8S cluster name'] == resultClusterName and
                                row['K8S namespace name'] == resultNamespaceName and
                                row['K8S workload type'] == resultWorkloadType and
                                row['K8S workload name'] == resultWorkloadName and
                                row['K8S container name'] == resultContainerName):
                                print(row['K8S cluster name'],"->",row['K8S namespace name'],"->",row['K8S workload type'],"->",row['K8S workload name'],"->",row['K8S container name'], row['Severity'], row['Package name'], row['Package version'], row['Vulnerability ID'])
                                severityCount += 1
                
                if(severityCount):
                    print(f"{RED}Total Critical: {severityCount}{RESET}")
                    