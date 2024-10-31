from .download_report import downloadReport
from .get_runtime_vuln_findings import vulnRuntimeFindings
import json
import time
import logging

def rerun_report(LOG, http_client, arg_secure_url_authority,arg_schedule_id):
    LOG.info("Rerunning report schedule...")

    url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/run"
    response = http_client.request(method="POST", url=url)
    LOG.debug(f"Response status: {response.status}")

    if not (200 <= response.status < 300):
        LOG.error(f"Error Quitting: {response.status}")
        quit()
        
    while True:
        url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/status"
        response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        json_response_data = json.loads(response.data.decode())
        LOG.debug(f"Response status: {response.status}")
        #print(json.dumps(json_response_data, indent=2))

        if not (200 <= response.status < 300):
            LOG.error(f"Error Quitting: {response.status}")
            quit()

        currentReportStatus = json_response_data.get("currentReport", {}).get("status", "completed")
        print(f"Report Status: {currentReportStatus.capitalize()}")

        if currentReportStatus not in ["scheduled", "progress"]:
            print("Processing latest report...")
            downloadReport(LOG, http_client, arg_secure_url_authority, arg_schedule_id)
            vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority)
            break
        else:
            time.sleep(1)
