# Runtime Vuln Reporting

### Pre-req:

1. Sysdig API Token

2. Runtime Workload Report defined under Vulnerabilities->Findings->Reportings



### Overview:

1. Retrieves all runtime vulnerabilities from Vulnerabilities->Runtime->Findings in Sysdig UI

2. Retrieves runtime workloads report from Vulnerabilities->Findings->Reportings

3. Print the runtime image information and individual CVEs that match the report



### Syntax: 

```
python3 run-report-schedule.py \

   --secure_url_authority app.us4.sysdig.com \

   --api_token abcde12345 \

   --schedule_id 2oA0OfdogY5CjfqyJLbuP8TW4tX
```
### Example Output:


```private-cluster -> test -> deployment -> insecuretest -> insecuretestcontainer Critical certifi 2020.4.5.1 CVE-2023-37920
private-cluster -> test -> deployment -> insecuretest -> insecuretestcontainer Critical Werkzeug 0.16.0 CVE-2022-29361
Total Critical: 222
private-cluster -> ac-test -> deployment -> test -> nginx Critical zlib1g 1:1.2.13.dfsg-1 CVE-2023-45853
private-cluster -> ac-test -> deployment -> test -> nginx Critical libaom3 3.6.0-1+deb12u1 CVE-2023-6879
private-cluster -> ac-test -> deployment -> test -> nginx Critical libheif1 1.15.1-1 CVE-2024-41311
Total Critical: 3
```