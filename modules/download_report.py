import urllib3
import json
import logging
import gzip
import shutil
import os
import http

def get_status_name(status_code):
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return "Unknown Status Code"

def downloadReport(LOG, http_client, arg_secure_url_authority, arg_schedule_id):
   # Check if the file "report" exists and delete it if it does
    report_file_path = 'report'
    if os.path.exists(report_file_path):
       os.remove(report_file_path)
       LOG.info(f"Deleted existing file: {report_file_path}")
    else:
        LOG.info(f"File does not exist: {report_file_path}")

    try:
        url = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/status"
        response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
    except Exception as e:
        LOG.error(f"An error occurred: {e}")
        quit()
    
    json_response_data = json.loads(response.data.decode())
    LOG.debug(f"Response status: {response.status}")
    
    if response.status != 200:
        LOG.error(f"Error Quitting: {response.status}")
        quit()

    #Download URL
    #/api/scanning/reporting/v2/schedules/2oA0OfdogY5CjfqyJLbuP8TW4tX/reports/2oA2scOpyT2UTb9lEuDN85plWGc/download

    downloadUrl = f"https://{arg_secure_url_authority}/api/scanning/reporting/v2/schedules/{arg_schedule_id}/reports/{json_response_data['lastCompletedReport']['reportId']}/download"

    # Download the gz file and save it to disk using http_client
    try:
        response = http_client.request(method="GET", url=downloadUrl, redirect=True, timeout=3)
    except Exception as e:
        LOG.error(f"An error occurred: {e}")
        quit()

    if response.status == 200:
        with open('report.gz', 'wb') as f:
            f.write(response.data)
        LOG.info("File downloaded successfully and saved as report.gz")
        
        # Decompress the gz file
        with gzip.open('report.gz', 'rb') as f_in:
            with open('report', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        LOG.info("File decompressed successfully and saved as report")
        
        # Delete the original report.gz file
        os.remove('report.gz')
        LOG.info("Original gz file deleted")
    else:
        LOG.error(f"Error Quitting, Received HTTP Status Code {response.status}: {get_status_name(response.status)}")