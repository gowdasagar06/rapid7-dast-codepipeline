Prerequisites:
1.create SSM parameter store  with parameter name as /ohana-api/appspec-insights/api-key add the api key 
2.AWS SSM parameter access to get API token
Python3 should be installed
boto3 should be installed

Go to rapid7 Insight:
setting --> API Key -> create API key and add store in SSM Parameter Store
Go to app section
Select add app
Choose scan my domain
provide domain name and run scan
It will take few seconds for
Queued
Provisioning
Ready to scan

It will take few minutes to scan all the endpoints in your domain
you will get scan config name copy the scan config name and application name which you used to create in previous steps to automate the process
and also you will get region name in beginning of rapid7 url(as subdomain), note the region name

There are 3 methods to scan
1. Using Rapid7 UI
2. Using API Tool like Postman
3. Using Automation Python Script

To Automate this process follow below steps:

1.Clone This repo:
https://github.com/rapid7/insightappsec-api-examples.git

2. navigate to insightappsec-api-examples/automation_use_cases/scan_automation  folder
cd insightappsec-api-examples/automation_use_cases/scan_automation/

you can see bin, lib, config and log folder 
ls

3. navigate to config/settings.yml file

change the file by providing your region name, application name, scan config name and status check interval

connection:
  region: us2
scan_info:
  - app_name: gowdasagar.online
    scan_config_name: http://gowdasagar.online
status_check_interval: 60


4. navigate to bin/main.py import boto3 library, add get_ssm_parameter function and reference api key in main function like below as
api_key = get_ssm_parameter("/ohana-api/appspec-insights/api-key")


import boto3

def get_ssm_parameter(name):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=True)
        return response['Parameter']['Value']
    except ssm_client.exceptions.ParameterNotFound:
        logging.error(f"Parameter {name} not found")
        raise
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"AWS credentials not found or incomplete: {e}")
        raise
    except Exception as e:
        logging.error(f"Error retrieving parameter {name}: {e}")
        raise

def main():
    if settings.get("connection"):
        api_key = get_ssm_parameter("/ohana-api/appspec-insights/api-key")
        region = settings.get("connection").get("region", "us")


5. navigate to /lib/helpers/insightappsec.py file and add get_vulnerabilities function inside class InsightAppSec at the end

    def get_vulnerabilities(self, scan_id):
        url = self.url + f"/vulnerabilities?query=vulnerability.scans.id='{scan_id}'"
        headers = self.headers

        try:
            response = requests.get(url=url, headers=headers)
            response.raise_for_status()

            vulnerabilities = response.json()
            return vulnerabilities
        except Exception as e:
            logging.error(f"Error in InsightAppSec API: Get Vulnerabilities\n{e}")
            raise e

6. navigate to /lib/helpers/scan_automation.py change below code in report_findings function 

def report_findings(api: InsightAppSec, scan_ids: [str], id_to_names: dict):
    """
    Given list of scan IDs, report on number of vulnerabilities found
    """
    logging.info("REPORTING VULNERABILITY DETAILS OF SCANS... (Scan ID, App Name, Scan Config Name): DETAILS")
    for scan_id in scan_ids:
        vulnerabilities = api.get_vulnerabilities(scan_id)
        num_findings = len(vulnerabilities.get("data", []))
        logging.info(f"({scan_id}, {id_to_names.get(scan_id)[0]}, {id_to_names.get(scan_id)[1]}: {num_findings} vulnerabilities found)")

        for vuln in vulnerabilities.get("data", []):
            vuln_id = vuln.get("id")
            severity = vuln.get("severity")
            description = vuln.get("description")
            logging.info(f"Vuln ID: {vuln_id}, Severity: {severity}, Description: {description}")

7. Navigate to scan_automation/bin folder and execute the main.py to scan your application:
python3 main.py & PYTHON_PID=$!; tail -f ../log/scan_automation.log & TAIL_PID=$!; wait $PYTHON_PID; kill $TAIL_PID




