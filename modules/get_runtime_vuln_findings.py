import urllib3
import json
import logging
from collections import defaultdict
from datetime import datetime
import http
import csv


def get_status_name(status_code):
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return "Unknown Status Code"
    
def vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority,vulndb_dict):
    RED = "\033[91m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    nextPage = True
    page = ""
    originalTotalEntries = 0
    newTotalEntries = 0
    progressCounter = 0
    vulndbSubstitionCounter = 0
 
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    outputFilename = f'results_{timestamp}.csv'


    # Add header to new report and overwrite if the file exists
    with open('report', mode='r') as source_file, open(outputFilename, mode='w', newline='') as destination_file:
        header = source_file.readline()
        # Add 'VulnDb' column header if vulndb_dict is not None
        if vulndb_dict is not None:
            header = header.strip() + ',VulnDb\n'
        destination_file.write(header)


    LOG.info("Getting Vuln->Findings->Runtime..")

    # Read the CSV file into memory and create a lookup dictionary
    csv_data = []
    lookup_dict = defaultdict(list)
    with open('report', mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            key = (row['Image ID'], row['K8S cluster name'], row['K8S namespace name'], row['K8S workload type'], row['K8S workload name'], row['K8S container name'])
            lookup_dict[key].append(row)
            csv_data.append(row)
        originalTotalEntries = len(csv_data)

    while nextPage:
        try:
            url = f"https://{arg_secure_url_authority}/api/scanning/runtime/v2/workflows/results?cursor={page}&filter&limit=1000&order=desc&sort=runningVulnsBySev&zones"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        except Exception as e:
            LOG.error(f"An error occurred: {e}")
            quit()
            
        LOG.debug(f"Response status: {response.status}")

        if response.status != 200:
            LOG.error(f"Error Quitting, Received HTTP Status Code {response.status}: {get_status_name(response.status)}")
            quit()

        json_response_data = json.loads(response.data.decode())

        # Check if there is a next page and if not exit the loop
        page = json_response_data.get("page", {}).get("next", "")

        if not page:
            nextPage = False
            
        # Get total count of runtime findings
        totalRuntimeFindings = json_response_data.get("page", {}).get("matched", "")

        # Collect rows to write in batch
        rows_to_write = []

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

            # Create the lookup key
            key = (resourceId, resultClusterName, resultNamespaceName, resultWorkloadType, resultWorkloadName, resultContainerName)

            # Retrieve matching rows from the lookup dictionary
            matching_rows = lookup_dict.get(key, [])
            for row in matching_rows:
                if vulndb_dict is not None:
                    vuln_id = row['Vulnerability ID']
                    if vuln_id in vulndb_dict:
                        row['VulnDb'] = vulndb_dict[vuln_id]
                        vulndbSubstitionCounter += 1
                    else:
                        row['VulnDb'] = row['Severity']

                rows_to_write.append(row.values())
                newTotalEntries += 1

            if progressCounter % 1000 == 0:
                print(f"{GREEN}Processing runtime assets {progressCounter} of {totalRuntimeFindings}...{RESET}")

        # Write collected rows to the output file in batch
        if rows_to_write:
            with open(outputFilename, mode='a', newline='') as results_file:
                csv_writer = csv.writer(results_file)
                csv_writer.writerows(rows_to_write)

    print(f"{BLUE}Total assets scanned: {totalRuntimeFindings}{RESET}")
    print(f"{BLUE}Total runtime report entries: {originalTotalEntries}{RESET}")
    print(f"{BLUE}Total entries for final report: {newTotalEntries}{RESET}")
    print(f"{BLUE}Total inactive runtime entries trimmed: {originalTotalEntries - newTotalEntries}{RESET}")
    if vulndb_dict is not None:
            print(f"{BLUE}Total vulndb severity transformations: {vulndbSubstitionCounter}{RESET}")
    print(f"{GREEN}Output report filename: {outputFilename}{RESET}")
