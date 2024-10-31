Runtime Vuln Reporting

Pre-req:

Sysdig API Token

Runtime Workload Report defined under Vulnerabilities->Findings->Reportings



Overview:

1. Retrieves all runtime vulnerabilities from Vulnerabilities->Runtime->Findings in Sysdig UI

2. Retrieves runtime workloads report from Vulnerabilities->Findings->Reportings


3. If results from runtime vulnerabilities match runtime workloads report pull the SBOM for that image

4. Print the runtime image information and individual CVEs that match the report



Syntax: 


python3 run-report-schedule.py \

   --secure_url_authority app.us4.sysdig.com \

   --api_token abcde12345 \

   --schedule_id 2oA0OfdogY5CjfqyJLbuP8TW4tX
