# Runtime Vuln Reporting

### Pre-req:

1. Sysdig API Token

2. Runtime Workload Report defined under Vulnerabilities->Findings->Reportings



### Overview:

1. Retrieves all runtime vulnerabilities from Vulnerabilities->Runtime->Findings in Sysdig UI

2. Retrieves runtime workloads report from Vulnerabilities->Findings->Reportings

3. Print the runtime image information and individual CVEs that match the report

4. Optionally adds a mapping to a user supplied vulndb excel sheet (--path_to_vulndb)

### Syntax: 

```
python3 run-report-schedule.py \

   --secure_url_authority app.us4.sysdig.com \

   --api_token abcde12345 \

   --schedule_id 2oA0OfdogY5CjfqyJLbuP8TW4tX \

   --path_to_vulndb "C:/temp/vulndb.xlsx"

```
### Example Output:


```
Retrieving status of report schedule for scheduleId := 2oA0OfdogY5CjfqyJLbuP8TW4tX...
The last report run completed at 2024-11-20 01:38:44 PM.
Would you like to rerun the report (yes/[no]): yes
Report Status: Scheduled
Report Status: Scheduled
Report Status: Scheduled
Report Status: Scheduled
Report Status: Scheduled
Report Status: Scheduled
Report Status: Progress
Report Status: Completed
Processing latest report...
Total assets scanned: 11
Total runtime report entries: 2092
Total entries for final report: 2092
Total inactive runtime entries trimmed: 0
Total vulndb severity transformations: 1443
Output report filename: results_20241122085324.csv
```