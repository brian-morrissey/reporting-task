import json
import logging
from collections import defaultdict
from datetime import datetime
import http

def get_status_name(status_code):
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return "Unknown Status Code"

def getReportSchedules(LOG, http_client, arg_secure_url_authority):
    nextPage = True
    page = ""

    # API endpoint doesnt support pagination currently but we will keep the logic in case it changes

    while nextPage:
        LOG.info("Getting Vuln->Findings->Runtime..")
        try:
            url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules?cursor={page}&filter&limit=100&order=desc"
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
        #page = json_response_data.get("page", {}).get("next", "")

        #if not page:
        #    nextPage = False

        nextPage = False    #Ignoring pages as it is not supported currently

        # Print the header
        print(f"{'Report Name':<90}{'    '}{'ID'}")
        print(f"{'-' * 90}{'    '}{'-' * 27}")

        # Print the report names
        try:
            for report in json_response_data:
                print(f"{report['name']:<90}{'    '}{report['id']}")
        except Exception as e:
            LOG.error(f"Error processing report names: {e}, Type: {type(e).__name__}")
            quit()
            
    