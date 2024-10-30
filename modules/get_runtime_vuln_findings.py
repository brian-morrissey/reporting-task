import urllib3
import json
import logging
import gzip
import shutil
import os
import csv
from collections import defaultdict


def vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority):
    RED = "\033[91m"
    RESET = "\033[0m"

    LOG.info("Getting Vuln->Findings->Runtime..")
    url = f"https://{arg_secure_url_authority}/api/scanning/runtime/v2/workflows/results?cursor&filter&limit=1&order=desc&sort=runningVulnsBySev&zones"
    response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
    json_response_data = json.loads(response.data.decode())
    LOG.debug(f"Response status: {response.status}")
    #print(json.dumps(json_response_data, indent=2))

    # Initialize matches and vuln_counts
    matches = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))))
    vuln_counts = defaultdict(lambda: defaultdict(int))

    # Loop through all results
    for result in json_response_data["data"]:
        severityCount = 0

        resultId = result["resultId"]
        resourceId = result["resourceId"]

        resultClusterName = result["recordDetails"]["labels"]["kubernetes.cluster.name"]
        resultNamespaceName = result["recordDetails"]["labels"]["kubernetes.namespace.name"]
        resultContainerName = result["recordDetails"]["labels"]["kubernetes.pod.container.name"]
        resultWorkloadName = result["recordDetails"]["labels"]["kubernetes.workload.name"]
        resultWorkloadType = result["recordDetails"]["labels"]["kubernetes.workload.type"]

        # Check for image in the report and skip downloading the SBOM if its not there to save time
        with open('report', 'r') as file:
            for line in file:
                if resourceId in line:
                    foundInReport = True

        if(foundInReport):
            LOG.info(f"Getting SBOM for resultId: {resultId}, resourceId: {resourceId}")
            url = f"https://{arg_secure_url_authority}/secure/vulnerability/v1beta1/sboms?assetId={resourceId}&assetType=container-image"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
            json_response_data = json.loads(response.data.decode())
            LOG.debug(f"Response status: {response.status}")
            #print(json.dumps(json_response_data, indent=2))

            # Extract the parameters name & version
            components = json_response_data["components"]

            for component in components:
                name = component["name"]
                version = component["version"]

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
                            row['K8S container name'] == resultContainerName):
                        
                            print(row['K8S cluster name'],"->",row['K8S namespace name'],"->",row['K8S workload type'],"->",row['K8S workload name'],"->",row['K8S container name'], row['Severity'], row['Package name'], row['Package version'], row['Vulnerability ID'])
                            severityCount += 1
            
            if(severityCount):
                print(f"{RED}Total Critical: {severityCount}{RESET}")
                