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
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    nextPage = True
    page = ""
    originalTotalEntries = 0
    newTotalEntries = 0
    totalRuntimeEntries = 0
    progressCounter = 0

    while nextPage:
        LOG.info("Getting Vuln->Findings->Runtime..")
        url = f"https://{arg_secure_url_authority}/api/scanning/runtime/v2/workflows/results?cursor={page}&filter&limit=100&order=desc&sort=runningVulnsBySev&zones"
        response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        json_response_data = json.loads(response.data.decode())
        LOG.debug(f"Response status: {response.status}")
 
        # Check if there is a next page and if not exit the loop
        page = json_response_data.get("page", {}).get("next", "")

        # pull total count
        totalRuntimeFindings = json_response_data.get("page", {}).get("matched", "")
        
        if not page:
            nextPage = False

        # Add header to new report and overwrite if the file exists
        with open('report', mode='r') as source_file, open('results.csv', mode='w', newline='') as destination_file:
            header = source_file.readline()
            destination_file.write(header)
            
        # Loop through all results
        for result in json_response_data["data"]:
            severityCount = 0
            progressCounter += 1

            try:
                resourceId = result["resourceId"]
                resultClusterName = result["recordDetails"]["labels"]["kubernetes.cluster.name"]
                resultNamespaceName = result["recordDetails"]["labels"]["kubernetes.namespace.name"]
                resultContainerName = result["recordDetails"]["labels"]["kubernetes.pod.container.name"]
                resultWorkloadType = result["recordDetails"]["labels"]["kubernetes.workload.type"]
                resultWorkloadName = result["recordDetails"]["labels"]["kubernetes.workload.name"]
            except KeyError as e:
                LOG.error(f"Missing key in result: {e}")
                LOG.error(f"Details of missing key: {result}")
                break
            
            # Open the file report which is CSV delimited
            with open('report', mode='r') as file:
                csv_reader = csv.DictReader(file)
                originalTotalEntries = sum(1 for _ in csv_reader)
                file.seek(0)
                # Iterate through each row in the CSV
                for row in csv_reader:
                    # Match the fields
                    if (row['Image ID'] == resourceId and
                        row['K8S cluster name'] == resultClusterName and
                        row['K8S namespace name'] == resultNamespaceName and
                        row['K8S workload type'] == resultWorkloadType and
                        row['K8S workload name'] == resultWorkloadName and
                        row['K8S container name'] == resultContainerName):
                        #print(row['K8S cluster name'],"->",row['K8S namespace name'],"->",row['K8S workload type'],"->",row['K8S workload name'],"->",row['K8S container name'], row['Severity'], row['Package name'], row['Package version'], row['Vulnerability ID'])
                        with open('results.csv', mode='a', newline='') as results_file:
                            csv_writer = csv.writer(results_file)
                            csv_writer.writerow(row.values())
                        severityCount += 1
                        newTotalEntries += 1
        
            if(severityCount):
                print(f"{RED}Total Critical for {resultClusterName}->{resultNamespaceName}->{resultWorkloadType}->{resultWorkloadName}->{resultContainerName}: {severityCount}{RESET}")
            if(progressCounter % 100 == 0):
                print(f"{GREEN}Processing runtime assets {progressCounter} of {totalRuntimeFindings}...{RESET}")

    print(f"{BLUE}Total runtime report entries: {originalTotalEntries}{RESET}")
    print(f"{BLUE}Total entries for final report: {newTotalEntries}{RESET}")
    print(f"{BLUE}Total inactive runtime entries trimmed {originalTotalEntries - newTotalEntries}{RESET}")
    print(f"{BLUE}Total assets scanned: {totalRuntimeFindings}{RESET}")