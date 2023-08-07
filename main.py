import datetime
import logging
import azure.functions as func
import base64
import re
import requests
import datetime
import time
import logging
import smtplib
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError
from azure.identity import DefaultAzureCredential
import os
import azure.functions as func
from azure.storage.blob import BlobServiceClient
import pyodbc
import struct

# Handle Exceptions and set Max Retries
session = requests.Session()
retry = HTTPAdapter(max_retries=5)
session.mount('https://', retry)

# Declare Authourization Headers
pat = os.environ.get('pat')
sonar_token = os.environ.get('sonar_token')
authorization = str(base64.b64encode(bytes(':'+pat, 'ascii')), 'ascii')
headers = {
'Accept': 'application/json',
'Content-Type': 'application/json',
'Authorization': 'Basic '+authorization
}

def send_mail():   
    import smtplib

    sender = 'alerts@jmfamily.com'
    receivers = ['convbmy@jmfamily.com']

    message = """From: QA-Security Gate Alerts <alerts@jmfamily.com>
    To: To Person <convbmy@jmfamily.com>
    Subject: Azure function down

    Check Logs
    """

    try:
        smtpObj = smtplib.SMTP('mailrelay.jmfamily.com')
        smtpObj.sendmail(sender, receivers, message)         
        print("Successfully sent email")
    except Exception as e:
        raise  e
    
def call_blob(abid,filename):
    '''Read Write builds to file'''        
    blob_service_client = BlobServiceClient.from_connection_string(os.environ.get('connection_string'))
    container_client = blob_service_client.get_container_client(container="qasecgatehelperfiles") 
    try:
        container_client = blob_service_client.get_container_client(container="qasecgatehelperfiles") 
        blob_client = container_client.get_blob_client(filename)
        all_builds = blob_client.download_blob().readall()
        ans = all_builds.decode('utf-8')
        ans_list = ans.split('\n')
        if abid in ans_list:
                return True
        else:
            build_id = '\n' + abid
            # Concatenate the existing string and new string
            concatenated_str = ans + build_id
            concatenated_data = concatenated_str.encode()
            blob_client.upload_blob(concatenated_data, overwrite=True)
            logging.warning('Added Build Record')
            return False
    except Exception as blob_error:
        logging.error(str(blob_error))
        send_mail()
        raise blob_error 


def db_connection():
    '''Connect to Azure SQL DB'''
    credential = DefaultAzureCredential() # system-assigned identity
    # Get token for Azure SQL Database and convert to UTF-16-LE for SQL Server driver
    token = credential.get_token("https://database.windows.net/.default").token.encode("UTF-16-LE")
    token_struct = struct.pack(f'<I{len(token)}s', len(token), token)
    # Connect with the token            
    SQL_COPT_SS_ACCESS_TOKEN = 1256
    conn_string = f"Driver={{ODBC Driver 17 for SQL Server}};SERVER=sql-to-dev-qasecgate.database.windows.net;DATABASE=QASecurityGatepoc"
    database_conn = pyodbc.connect(conn_string, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct})            
    database_cursor = database_conn.cursor()
    return database_conn, database_cursor

def get_azure_projects():
    main_url = os.environ.get('main_url')
    '''Get Azure Projects'''
    try:
        projects_resp = session.get(main_url, headers=headers, timeout=10).json()
        projects = projects_resp['value']
    except ConnectionError as project_api_error:
        logging.warning(str(project_api_error))
        send_mail()
        raise project_api_error        
    return projects


def get_builds(projects):       
    '''Get Azure Pipeline Builds'''        
    for project in projects:
        #Project ID
        project_id = project['id']
        #Get all Builds for the project
        date = (2022,4,4)
        # Convert the date tuple to a datetime object
        date = datetime.datetime(*date)
        try:
            builds = session.get(f"https://dev.azure.com/JM-FAMILY/{project_id}/_apis/build/builds?api-version=6.0&minTime={date.isoformat()}Z", headers=headers,timeout=10).json()
        except ConnectionError as builds_api_error:
            logging.error(str(builds_api_error))
            send_mail()
        get_results(project_id,builds)
        #send_results(builds, connection, cur)

def get_key(logs):
    '''Azure sonar Key'''
    for item in logs:
        if 'INFO: Project key:' in item:
            key_split = item.split('key: ')
            logging.warning('{}'.format(key_split))
            project_key = key_split[1 ]
            break
        else:
            project_key = None

    return project_key
    

def check_sonar(logs):
    '''Check for sonar run in Azure logs'''
    for item in logs:
        if 'ANALYSIS SUCCESSFUL' in item:
            url1= item.split('http')
            sonar_url = 'http' + url1[1]
            sonar_run = 'Yes'
            break
        else:
            sonar_run = 'No'
            sonar_url = 'Scan not Run'
    if '&branch' in sonar_url:
        branch_split = item.split('&branch=')
        branch = branch_split[1]
    else:
        branch = None
    logging.warning("BRANCH IS {}".format(branch))
    return sonar_run, sonar_url, branch

def sonar_results(key,pname,plinename,id,bran):
    '''Azure Sonar Results'''
    global no_val
    no_val = 'Not Found'
    # Set the base URL for the SonarQube API
    base_url = os.environ.get('sonar_base')
    # Build the URL for the API call
    if bran:
        url = f"{base_url}?component={key}&metricKeys=alert_status,code_smells,security_rating,violations,bugs,coverage,duplicated_lines_density&buildId={id}&branch={bran}"
    else:
        url = f"{base_url}?component={key}&metricKeys=alert_status,code_smells,security_rating,violations,bugs,coverage,duplicated_lines_density&buildId={id}"

    try:
        session = requests.Session()
        session.auth = f'{sonar_token}', ''
        call = getattr(session, 'get')
        res = call(url)
        data = res.json()
        alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating = sonar_data(data)
        if violations.isdigit() and int(violations) > 1:
            logging.warning("I AM HERE {}".format(bran))
            if bran:
                url = f"https://sonarqube.jmfamily.com/api/issues/search?componentKeys={key}&ps=500&&buildId={id}&branch={bran}"
            else:
                url = f"https://sonarqube.jmfamily.com/api/issues/search?componentKeys={key}&ps=500&&buildId={id}"

            logging.warning('Calling Sonar at {}'.format(url))
            session = requests.Session()
            session.auth = f'{sonar_token}',''
            call = getattr(session, 'get')
            res = call(url)
            data = res.json()

            for item in data['issues']:
                severity = item['severity']
                issue_typ = item['type']
                message = item['message']
                isu_status = item['status']
                isu_date = item['updateDate']
                conn, cur = db_connection()
                pipe_type = 'Azure'                        
                role=''        
                logging.warning('{}'.format('Inserting Sonar Results'))
                sql_command = "INSERT INTO SonarQubeResultsData ([PipelineType], [LineOfBusiness],[ApplicationName],[Role],[BuildId],[UpdatedOn],[Severity],[Type],[Status],[Message]) VALUES (?,?,?,?,?,?,?,?,?,?);"
                cur.execute(sql_command,(pipe_type,pname,plinename,role,id,isu_date,severity,issue_typ,isu_status,message))    
                conn.commit()       

    except KeyError:
        pass
    except Exception as sonar_error:
        logging.warning(str(sonar_error))
        send_mail()
        raise sonar_error

    # logging.warning('*SONAR RESULTS* {}{}{}{}{}{}'.format(alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating))

    return alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating
        


def get_results(prid,builds):
    '''Scan Azure Logs'''
    global alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating
    
    for item in builds['value']:
        try:
            build_number = str(item['id'])
            if call_blob(build_number,'AZURE_BUILD_IDS.txt'):
                continue
            
            project_name = str(item['project']['name'])
            pipeline_def = item['definition']
            pipeline_name = pipeline_def['name']
            build_result = str(item.get('result', 'Not Available'))
            build_start = str(item.get('startTime', 'Not Available'))
            build_runbyn = str(item['requestedBy']['displayName'])
            
            logs_all = session.get(f'https://dev.azure.com/JM-FAMILY/{prid}/_apis/build/builds/{build_number}/logs', headers=headers, timeout=10).json()
            str2 = logs_all['value']
            ans1 = [it['id'] for it in str2]
            logs = session.get(f'https://dev.azure.com/JM-FAMILY/{prid}/_apis/build/builds/{build_number}/logs/{ans1[-2]}', headers=headers, timeout=10)
            logs_var = logs.content
            logs_f = logs_var.decode("utf-8")
            new_var = logs_f.split('","')
            result = check_sonar(new_var)
            sonar_run, sonar_url, bran = result[0], result[1], result[2]
            
            if sonar_run == 'Yes':
                pkey = get_key(new_var)
                if pkey:
                    alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating = sonar_results(pkey,project_name,pipeline_name,build_number,bran)
                    pipeline_type= 'Azure'
                    domain= ''
                    role=''
                    build_name = ''
                    conn, cur = db_connection()
                    sr_sql_command = "INSERT INTO PipelineParsedData ([PipelineType], [LineOfBusiness],[Domain], [ApplicationName],[Role],[BuildNumber],[BuildStartedByName],[BuildTimestamp],[BuildResult],[BuildName],[SonarScanCalled],[SonarScanURL],[SonarScanResult],[Violations],[DuplicatedLines],[Bugs],[CodeSmells],[SecurityRating]) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);"
                    cur.execute(sr_sql_command,(pipeline_type,project_name,domain,pipeline_name,role,build_number,build_runbyn,build_start,build_result,build_name,sonar_run,sonar_url,alert_status,violations,duplicated_lines_density,bugs,code_smells,security_rating))    
                    conn.commit()       

                        
            else:
                alert_status = ''
                violations = ''
                duplicated_lines_density = ''
                bugs = ''
                code_smells = '' 
                security_rating = ''
                pipeline_type= 'Azure'
                domain= ''
                role=''
                build_name = ''
                conn, cur = db_connection()
                srn_sql_command ="INSERT INTO PipelineParsedData ([PipelineType], [LineOfBusiness],[Domain], [ApplicationName],[Role],[BuildNumber],[BuildStartedByName],[BuildTimestamp],[BuildResult],[BuildName],[SonarScanCalled],[SonarScanURL],[SonarScanResult],[Violations],[DuplicatedLines],[Bugs],[CodeSmells],[SecurityRating]) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);"
                cur.execute(srn_sql_command,(pipeline_type,project_name,domain,pipeline_name,role,build_number,build_runbyn,build_start,build_result,build_name,sonar_run,sonar_url,alert_status,violations,duplicated_lines_density,bugs,code_smells,security_rating))    
                conn.commit()       
        except Exception as azure_results_error:
            send_mail()
            logging.exception(str(azure_results_error))
            

''' AWS Solution'''

start_date = datetime.datetime(2022, 4, 4)
start_timestamp = int(start_date.timestamp() * 1000)

# Set Jenkins server URL
JENKINS_URL = os.environ.get('jenkins_url')
access_token = os.environ.get('jenkins_token')
    
def get_key(logs):
    # Get the Project Key for Sonar Qube
    for item in logs:
        if 'INFO: Project key:' in item:
            key_split = item.split(' ')
            logging.warning(key_split)
            project_key = key_split[-1]
            project_key = project_key.replace('\r','')
            logging.warning(project_key)
            break
        else:
            project_key = None

    return project_key

def sonar_data(res):

    no_val = 'Not Found'
    measures_dict = {
        'code_smells': 'code_smells',
        'duplicated_lines_density': 'duplicated_lines_density',
        'security_rating': 'security_rating',
        'coverage': 'coverage',
        'bugs': 'bugs',
        'alert_status': 'alert_status',
        'violations': 'violations'
    }
    results = {
        'alert_status': no_val,
        'violations': no_val,
        'duplicated_lines_density': no_val,
        'bugs': no_val,
        'code_smells': no_val,
        'security_rating': no_val
    }

    for item in res['component']['measures']:
        metric = item.get('metric')
        value = item.get('value')

        if all([metric, value, metric in measures_dict]):
            var_name = measures_dict[metric]
            results[var_name] = value

    return (
        results['alert_status'],
        results['violations'],
        results['duplicated_lines_density'],
        results['bugs'],
        results['code_smells'],
        results['security_rating']
    )



def aws_sonar_results(key,id,lob,app,app_role):
    # Get Sonar Scan Results
    # Set the base URL for the SonarQube API
    base_url = os.environ.get('sonar_base')
    issue_url = os.environ.get('sonar_issue_url')
    url = f"{base_url}?component={key}&metricKeys=alert_status,code_smells,security_rating,violations,bugs,coverage,duplicated_lines_density&buildId={id}"
    session = requests.Session()
    session.auth = f'{sonar_token}', ''
    call = getattr(session, 'get')

    try:
            res = call(url)
    except ConnectionError as sonar_connerror:
            send_mail()
            logging.error(str(sonar_connerror))
            return None, None, None, None, None, None
    resp = res.json()
    
    alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating = sonar_data(resp)
    if int(violations) > 1:
        url = f"{issue_url}componentKeys={key}&ps=500&&buildId={id}"
        session = requests.Session()
        session.auth = f'{sonar_token}',''
        call = getattr(session, 'get')
        res = call(url)
        data = res.json()
        severity = ''
        issue_typ = ''
        message = ''
        isu_status = ''
        isu_date = ''
        for item in data['issues']:
            severity = item['severity']
            issue_typ = item['type']
            message = item['message']
            isu_status = item['status']
            isu_date = item['updateDate']
            conn, cur = db_connection()
            pipe_type = 'AWS'                                            
            try:           
                logging.warning('{}'.format('Inserting AWS Sonar Results into'))
                sql_command = "INSERT INTO SonarQubeResultsData ([PipelineType], [LineOfBusiness],[ApplicationName],[Role],[BuildId],[UpdatedOn],[Severity],[Type],[Status],[Message]) VALUES (?,?,?,?,?,?,?,?,?,?);"
                cur.execute(sql_command,(pipe_type,lob,app,app_role,id,isu_date,severity,issue_typ,isu_status,message))    
                conn.commit()       
            except Exception as son_res_aws_db_error:
                send_mail()
                logging.warning(son_res_aws_db_error)
                raise son_res_aws_db_error
    
    return alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating


def scan_aws_build(job):
    global auth, access_token,JENKINS_URL,jenuser,no_val
    # Get info from Build URLs
    jenuser = os.environ.get('jenkins_username')
    auth = (jenuser,access_token)
    pipeline_type = 'AWS'
    try:
        logging.warning("Build Found, sleeping for 3 seconds")
        build_url = job + 'api/json'
        logging.warning(str(build_url))
        builds = session.get(build_url, auth=auth,stream=True).json()
        try:
            resp = builds['builds'][0]['url']
        except IndexError:
            return 'Err'
        logging.warning(str(resp))
        log_info_url = resp + 'api/json/'
        logs_info = session.get(log_info_url, auth=auth, stream=True).json()
        logging.warning(str(log_info_url))
        init_time = int(logs_info['timestamp'])
        try:
            started_by = logs_info['actions'][0]['causes'][0]['shortDescription']
        except:
            started_by = 'No User Found' #logs_info['actions']['causes'][0]['shortDescription']
        if init_time < start_timestamp:
            logging.warning("OLD BUILD")
            return 'OLD'
        divhun = init_time / 1000
        build_run_at  = datetime.datetime.fromtimestamp(divhun).strftime('%Y-%m-%d %H:%M:%S')
        logging.warning(str(build_run_at))
        build_result = logs_info['result']
        logging.warning(str(build_result))
        build_name = logs_info['fullDisplayName']
        logging.warning(str(build_name))
        log_url = resp + 'consoleText' 
        logging.warning(str(log_url))
        if call_blob(log_url,'AWS_BUILD_IDS.txt'):
            return 'Scanned'
        count = log_url.count('job/')
        if count == 5:
            split1 = log_url.split('com/job')
            root_split = split1[1].split('/')
            lob = root_split[1]
            build_no = root_split[-2]
            logging.warning(str(build_no))
            domain = 'No Domain'
            logging.warning(str(domain))
            app_name = root_split[3]
            logging.warning(str(app_name))
            role = root_split[5]
            logging.warning(str(role))
        elif count == 6:
            split1 = log_url.split('com/job')
            root_split = split1[1].split('/')
            lob = root_split[1]
            logging.warning(str(lob))
            build_no = root_split[-2]
            logging.warning(str(build_no))
            domain = root_split[3]
            logging.warning(str(domain))
            app_name = root_split[5]
            logging.warning(str(app_name))
            role = root_split[7]
            logging.warning(str(role))
        else:
            build_no = no_val
            lob = no_val
            domain = no_val
            role = no_val
            app_name = no_val

        logs = session.get(log_url, auth=auth).text
        logging.warning("Logs Found. Sleeping for 2 seconds")
        time.sleep(2)
        logs = logs.split('\n')
        logging.warning("SCANNING LOGS...") 
        for log in logs:
            if 'ANALYSIS SUCCESSFUL' in log:
                logging.warning('Sonar has run')
                sonar_url_split = log.split(' ')
                sonar_scan = 'Yes'
                sonar_url = sonar_url_split[-1]
                pkey = get_key(logs)
                if pkey:                   
                    conn, cur = db_connection()
                    alert_status, violations, duplicated_lines_density, bugs, code_smells, security_rating = aws_sonar_results(pkey,build_no,lob,app_name,role)
                    logging.warning('Sonar Run DB AWS, Inserting Data...')                    
                    sql_command = "INSERT INTO PipelineParsedData ([PipelineType], [LineOfBusiness],[Domain], [ApplicationName],[Role],[BuildNumber],[BuildStartedByName],[BuildTimestamp],[BuildResult],[BuildName],[SonarScanCalled],[SonarScanURL],[SonarScanResult],[Violations],[DuplicatedLines],[Bugs],[CodeSmells],[SecurityRating]) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);"
                    cur.execute(sql_command,(pipeline_type,lob,domain,app_name,role,build_no,started_by,build_run_at,build_result,build_name,sonar_scan,sonar_url,alert_status,violations,duplicated_lines_density,bugs,code_smells,security_rating))    
                    conn.commit()
                    return 'SR'   


            else:                
                sonar_scan = 'No'
                sonar_url = 'Sonar Scan not run'                      
                alert_status = ''
                violations = ''
                duplicated_lines_density = ''
                bugs = ''
                code_smells = '' 
                security_rating = ''
        conn, cur = db_connection()
        logging.warning('Sonar NOT Run DB')
        # logging.warning('Sonar Results are {}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}'.format(pipeline_type,project_name,domain,pipeline_name,role,build_number,build_runbyn,build_start,build_result,build_name,sonar_run,sonar_url,alert_status,violations,duplicated_lines_density,bugs,code_smells,security_rating))
        sql_command = "INSERT INTO PipelineParsedData ([PipelineType],[LineOfBusiness],[Domain], [ApplicationName],[Role],[BuildNumber],[BuildStartedByName],[BuildTimestamp],[BuildResult],[BuildName],[SonarScanCalled],[SonarScanURL],[SonarScanResult],[Violations],[DuplicatedLines],[Bugs],[CodeSmells],[SecurityRating]) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);"
        cur.execute(sql_command,(pipeline_type,lob,domain,app_name,role,build_no,started_by,build_run_at,build_result,build_name,sonar_scan,sonar_url,alert_status,violations,duplicated_lines_density,bugs,code_smells,security_rating))    
        conn.commit()
        return 'SNR'   

        
    except Exception as aws_scan_error:
        send_mail()
        logging.warning(str(aws_scan_error))
        raise aws_scan_error

def check_build_folder(url):
    logging.warning("Checking AWS Builds...")
    # Check if Build exists in the current Job
    iurl = url + 'api/json?tree=jobs[name,url]'
    logging.warning(str(iurl))
    folder_jobs = session.get(iurl, auth=auth,stream=True).json()
    try:
        for job in folder_jobs['jobs']:
            if 'Build' not in job['name']:
                check_build_folder(job['url'])
            else:
                check_url = job['url'] + '/api/json'
                logging.warning(str(check_url))
                time.sleep(1)
                pub_job = session.get(check_url, auth=auth,stream=True).json()
                for job in pub_job['jobs']:
                    if re.search(r'\BuildTestAndPublish\b', job['url']) or re.search(r'\BuildAndPublishNuget\b', job['url']):
                        scan_aws_build(job['url'])
                    else:
                        continue
    except KeyError:
        pass
    except Exception as aws_build_error:
        send_mail()
        logging.warning(str(aws_build_error))
        
def get_aws_projects():
    global JENKINS_URL,auth,jenuser
    jenuser = os.environ.get('jenkins_username')
    auth = (jenuser,access_token)
    # Get a list of all jobs from root folders
    try:
        projects_api = session.get(JENKINS_URL + '/api/json', auth=auth,stream=True).json()
        for root_folder in projects_api['jobs']:
            root_folder_job_url = JENKINS_URL + '/job/'+ root_folder['name']+'/api/json?tree=jobs[name,url]'
            logging.warning(str(root_folder_job_url))
            root_jobs = session.get(root_folder_job_url, auth=auth,stream=True).json()
            for r_job in root_jobs['jobs']:
                logging.warning(str(r_job['url']))
                check_build_folder(r_job['url'])
                
    except Exception as project_error:
        logging.error("Programme Error")
        send_mail()
        raise project_error


def main(mytimer: func.TimerRequest):
    if mytimer.past_due:
        logging.info('The timer is past due!')
    while True:
        logging.warning('{}'.format('Scanning Azure Logs'))
        azure_projs = get_azure_projects()
        get_builds(azure_projs)
        logging.warning('{}'.format('Getting AWS Scans...'))            
        get_aws_projects()
        logging.warning('{}'.format('Sleepin Now for 15 minutes'))
        time.sleep(90)
