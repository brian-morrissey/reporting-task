from .download_report import downloadReport
from .get_runtime_vuln_findings import vulnRuntimeFindings
import json
import time
import logging
import http

def get_status_name(status_code):
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return "Unknown Status Code"
    
def rerun_report(LOG, http_client, arg_secure_url_authority,arg_schedule_id):
    LOG.info("Rerunning report schedule...")

    url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/run"
    response = http_client.request(method="POST", url=url)
    LOG.debug(f"Response status: {response.status}")

    if not (200 <= response.status < 300):
        LOG.error(f"Error Quitting, Received HTTP Status Code {response.status}: {get_status_name(response.status)}")
        quit()
        
    while True:
        try:
            url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/status"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        except Exception as e:
            LOG.error(f"An error occurred: {e}")
            quit()

        LOG.debug(f"Response status: {response.status}")

        if not (200 <= response.status < 300):
            LOG.error(f"Error Quitting, Received HTTP Status Code {response.status}: {get_status_name(response.status)}")
            quit()

        json_response_data = json.loads(response.data.decode())

        currentReportStatus = json_response_data.get("currentReport", {}).get("status", "completed")
        print(f"Report Status: {currentReportStatus.capitalize()}")

        if currentReportStatus not in ["scheduled", "progress"]:
            print("Processing latest report...")
            downloadReport(LOG, http_client, arg_secure_url_authority, arg_schedule_id)
            vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority)
            break
        else:
            time.sleep(1)
