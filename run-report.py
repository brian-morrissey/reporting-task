"""
  This python script will create a runtime report schedule.

  Author: Kendall Adkins
  Author: Brian Morrissey
  Date November 1st, 2024
"""

import argparse
import logging
import sys
import urllib3
import json
from datetime import datetime
from datetime import timedelta
from dateutil import tz
import time
import os.path
import os
from modules.get_runtime_vuln_findings import vulnRuntimeFindings
from modules.download_report import downloadReport
from modules.rerun_report import rerun_report
from modules.get_report_schedules import getReportSchedules

# Setup logger
LOG = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Setup http client
http_client = urllib3.PoolManager()

# Track number of http response codes
num_of_429 = 0
num_of_504 = 0

# Will be set by a passed arg
arg_secure_url_authority = ""

# Define custom exceptions
class UnexpectedHTTPResponse(Exception):
    """Used when recieving an unexpected HTTP response"""

def _parse_args():

    args = None

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--secure_url_authority",
        required=True,
        type=str,
        action="store",
        help="authority component of secure url",
    )
    parser.add_argument(
        "--api_token",
        required=True,
        type=str,
        action="store",
        help="Sysdig Secure API Token",
    )
    parser.add_argument(
        "--schedule_id",
        required=True,
        type=str,
        action="store",
        help="Sysdig Runtime Report Schedule ID",
    )
    parser.add_argument(
        "--list_schedules",
        required=False,
        action="store_true",
        help="List Sysdig Runtime Report Schedule IDs (can not be used with other params)",
    )
    parser.add_argument(
        "--debug",
        required=False,
        action="store_true",
        help="Set logging to debug level",
    )
    return parser.parse_args()

def main():
        # Parse the command line arguments
        args = _parse_args()
        global arg_secure_url_authority
        arg_secure_url_authority = args.secure_url_authority
        arg_authentication_bearer = args.api_token
        arg_schedule_id = args.schedule_id

        # Turn on debug logging if requested in args
        if args.debug:
            LOG.setLevel(logging.DEBUG)

        # Get the timestamp of this run
        now = datetime.now()
        current_datetime = now.strftime("%Y-%m-%d %H:%M")

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {arg_authentication_bearer}"
        http_client.headers["Accept"] = "application/json"
        http_client.headers["Content-Type"] = "application/json"

        # Start performance counter
        pc_start = time.perf_counter()

        # Get List of Scheduled Reports if flag is present and quit
        if args.list_schedules:
            getReportSchedules(LOG, http_client, arg_secure_url_authority)
            quit()


        #---------------------------
        # Get Report Schedule
        #----------------------------
        LOG.info(f"Retrieving report schedule for scheduleId := {arg_schedule_id}...")
        try:
            url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        except Exception as e:
            LOG.error(f"An error occurred: {e}")
            quit()
        if response.status == 200:
            json_response_data = json.loads(response.data.decode())
            scheduleId = json_response_data['id']
            scheduleName = json_response_data['name']
            LOG.info(f"scheduleId := {scheduleId}")
            LOG.info(f"scheduleName := {scheduleName}")
            #print(json.dumps(json_response_data, indent=2))

            #Exit if report is not for runtime workloads, gz compressed, and csv export
            if json_response_data.get("entityType", {}) != "k8s":
                LOG.error(f"Exiting!! Report entity is for {json_response_data.get("entityType", {})} scan and not a runtime workloads. Please use a runtime workloads report.")
                raise SystemExit(-1)
            elif json_response_data.get("compression", {}) != "gz":
                LOG.error(f"Exiting!! Report compression is {json_response_data.get("compression", {})} and not gz. Please use a gz compression in report.")
                raise SystemExit(-1)
            elif json_response_data.get("reportFormat", {}) != "csv":
                LOG.error(f"Exiting!! Report export file format is {json_response_data.get("reportFormat", {})} and not csv. Please use a csv for export file format in report.")
                raise SystemExit(-1)
            
        elif response.status == 404:
            LOG.error(f"Exiting!! Report schedule not found for scheduleId := {arg_schedule_id}")
            raise SystemExit(-1)
        elif response.status == 401:
            LOG.error(f"Exiting!! Unauthorized token access to report schedule for scheduleId := {arg_schedule_id}")
            raise SystemExit(-1)
        else:
            raise UnexpectedHTTPResponse(
                f"Unexpected HTTP response status: {response.status}"
            )

        #---------------------------
        # Get Last Generated Report Status
        #----------------------------
        print(f"Retrieving status of report schedule for scheduleId := {scheduleId}...")
        try:
            url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/status"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        except Exception as e:
            LOG.error(f"An error occurred: {e}")
            quit()

        LOG.debug(f"Response status: {response.status}")
        if response.status == 200:

            reportScheduleStatus = json.loads(response.data.decode())
            currentReportRun = reportScheduleStatus.get('currentReport', None)
            lastReportRun = reportScheduleStatus.get('lastCompletedReport', None)

            runNewReport = False

            if currentReportRun is None and lastReportRun is None:
                runNewReport = True

            elif currentReportRun is None:
                lastReportRunCompletedAt = lastReportRun['completedAt']
                dt_lastReportRunCompletedAt = datetime.fromisoformat(lastReportRunCompletedAt.replace("Z", "+00:00"))
                local_timezone = tz.tzlocal()
                local_dt_lastReportRunCompletedAt = dt_lastReportRunCompletedAt.astimezone(local_timezone).strftime("%Y-%m-%d %I:%M:%S %p")
                print(f"The last report run completed at {local_dt_lastReportRunCompletedAt}.")
                prompt_runReport = input(f"Would you like to rerun the report (yes/[no]): ")

                if prompt_runReport.lower() in ['yes','y']:
                    runNewReport = True
                         
        else:
            raise UnexpectedHTTPResponse(
                f"HTTP STATUS {response.status}: Error getting report schedule status for {arg_schedule_id}" 
            )

        # Use existing report or run new report based on previous user input
        if not runNewReport:
            print("Using last report schedule run...")
            try:
                url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/status"
                response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
            except Exception as e:
                LOG.error(f"An error occurred: {e}")
                quit()

            json_response_data = json.loads(response.data.decode())
            LOG.debug(f"Response status: {response.status}")
            #print(json.dumps(json_response_data, indent=2))

            if not (200 <= response.status < 300):
                LOG.error(f"Error Quitting: {response.status}")
                quit()

            hasReportEverRun = json_response_data.get("lastCompletedReport", {})
            
            if (not hasReportEverRun):
                print("No report has been generated before. Running new report...")
                rerun_report(LOG, http_client, arg_secure_url_authority, arg_schedule_id)
            else:                
                downloadReport(LOG, http_client, arg_secure_url_authority, arg_schedule_id)
                vulnRuntimeFindings(LOG, http_client, arg_secure_url_authority)
        else:
            rerun_report(LOG, http_client, arg_secure_url_authority, arg_schedule_id)
   
        # Cleanup - Check if the file "report" exists and delete it if it does
        report_file_path = 'report'
        if os.path.exists(report_file_path):
          os.remove(report_file_path)
          LOG.info(f"Deleted existing file: {report_file_path}")
        else:
          LOG.info(f"File does not exist: {report_file_path}")
            
        # End performance counter
        pc_end = time.perf_counter()
        elapsed_seconds = pc_end - pc_start
        execution_time = "{}".format(str(timedelta(seconds=elapsed_seconds)))

        LOG.debug(f"Elapsed execution time: {execution_time}")
        LOG.debug(f"HTTP Response Code 429 occurred: {num_of_429} times.")
        LOG.debug(f"HTTP Response Code 504 occurred: {num_of_504} times.")
        LOG.info(f'Request for runtime scan results complete.')

if __name__ == "__main__":
    sys.exit(main())
