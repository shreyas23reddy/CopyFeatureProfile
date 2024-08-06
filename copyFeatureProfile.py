import logging
import requests
import json
import datetime
import os
import os.path
import random
import shutil
import pwinput
from tqdm import tqdm
import re

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(filename='script_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


cwd = os.getcwd()


zip_file_name = str(random.randint(111000, 9999999))

if os.name == 'nt':
    r_path = cwd + '\\' + zip_file_name
elif os.name == 'posix':
    r_path = cwd + '/' + zip_file_name
try:
    if not os.path.exists(r_path):
        os.mkdir(r_path)
except OSError as e:
    logging.error("Creation of the directory %s failed" % r_path)

def get_jsession(response):
    logging.info("********Inside get_jsession function*******")
    jsession_id = ''
    try:
        if response:
            if response.status_code == 200:
                cookies = response.headers["set-cookie"] if "set-cookie" in response.headers else response.headers["Set-Cookie"]
                if cookies:
                    jsessionid = cookies.split(";")
                    return jsessionid[0]
    except Exception as e:
        logging.exception("No valid JSESSION ID returned\n" + str(e))
    return jsession_id

def generate_jsession(base_url, username, password):
    try:
        logging.info("*******Inside the get_jsession id function*********")
        url = base_url + "/j_security_check"
        payload = {'j_username' : username, 'j_password' : password}
        url_without_port = ':'.join(base_url.split(':')[:-1]) + "/j_security_check"
        response = {}
        try:
            logging.info("****Get jsession_id without port :: *******{}*************".format(url_without_port))
            response = requests.post(url=url_without_port, data=payload, verify=False)
            logging.info('status_code without port form get jsession_id' + str(response.status_code))
        except Exception as e:
            logging.exception("Expcetion while getting jsession id without port \n" + str(e))
        jsession_id = get_jsession(response)
        if jsession_id == '':
            logging.info("****Get jsession_id with port :: *******{}*************".format(url))
            try:
                response = requests.post(url=url, data=payload, verify=False)
                logging.info('status_code with port form get jsession_id' + str(response.status_code))
            except Exception as e:
                logging.exception("Expcetion while getting jsession id with port \n" + str(e))
            jsessionid = get_jsession(response)
            return jsessionid, 'port'
        else:
            return jsession_id, ''

    except Exception as e:
        logging.exception('Exception inside generate_jsession' + str(e))
    return None, 400

def get_token(base_url, username,password):
    try:
        logging.info("*******Inside the token function*********")
        jsessionid, cond = generate_jsession(base_url,username,password)
        if jsessionid:
            headers = {'Cookie': jsessionid}
            url = base_url + "/dataservice/client/token"
            url_without_port = ':'.join(base_url.split(':')[:-1]) + "/dataservice/client/token"
            if cond != 'port':
                logging.info("****Get token without port :: *******{}*************".format(url_without_port))
                response = requests.get(url=url_without_port, headers=headers, verify=False)
                logging.info('status_code without port form get token' + str(response.status_code))
            else:
                logging.info("****Get token with port :: *******{}*************".format(url))
                response = requests.get(url=url, headers=headers, verify=False)
                logging.info('status_code with port form get token' + str(response.status_code))
            if response.status_code == 200:
                return response.text, jsessionid
    except Exception as e:
        logging.exception('Exception inside get_token' + str(e))
    return None, 400

def api_checks_execution_pagination(header,base_url, endpoint, feature_profile_name):
    try:
        limit = 10
        count = 0 
        pageResponse = None
       
        
        while pageResponse == None :
            
            offset = count * limit
            query = f"?offset={offset}&limit={limit}"
            url = base_url+ endpoint + query
            response = api_checks_execution(header, url)
            count += 1
            
            for iter in response:
                if iter["profileName"] == feature_profile_name:
                    pageResponse = iter
                    break
            
            if response == []:
                logging.error("unable to find the Feature profile name provide please retry ")
                break
        
        
        return pageResponse
                    
    except Exception as e:
        logging.exception('Exception inside get_token' + str(e))
    

def api_checks_execution(header,url):
    try:
        logging.info("GET REQUEST - url  = " + str(url))
        api_response = requests.get(url, verify=False, headers=header)
        logging.info("api_response.raise_for_status = " + str(api_response.raise_for_status()))
        api_response.raise_for_status()
        if api_response.status_code == 200:
            return api_response.json()
    except Exception as e:
        logging.exception('Exception inside api_checks_execution' + str(e))
        logging.exception('FAILED: Not able to get ' + str(url))
    return None, 400

def api_post_execution(header,url, payload):
    try:
        logging.info("POST request - url = " + str(url))
        api_response = requests.post(url, verify=False, headers=header, data=json.dumps(payload))
        logging.info("api_response.raise_for_status = " + str(api_response.raise_for_status()))
        api_response.raise_for_status()
        if api_response.status_code == 200:
            return api_response.json()
    except Exception as e:
        logging.exception('Exception inside api_checks_execution' + str(e))
        logging.exception('FAILED: Not able to get ' + str(url))
    return None, 400



def ziptron(ip_address, port, admin_username, admin_password, feature_profile_name):
    logging.info(r_path)
    base_url = "https://%s:%s"%(ip_address, port)
    token_var, jsessionid = get_token(base_url, admin_username, admin_password)
    if token_var is not None and jsessionid != 400:
        api_header = {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token_var}
    elif jsessionid != 400:
        api_header = {'Content-Type': "application/json", 'Cookie': jsessionid}
    else:
        logging.error('********Could not run the checks*******')
        return {'msg': 'Could not run the checks'}
    
    endpoint = "/dataservice/v1/feature-profile/sdwan"
    oldFeatureProfile = api_checks_execution_pagination(api_header, base_url, endpoint, feature_profile_name)
    
    logging.info("Successfully matched feature profile now extracting the info")
    
    geturl = base_url + endpoint + "/" + oldFeatureProfile["profileType"] + "/" + oldFeatureProfile["profileId"]
    response = api_checks_execution(header=api_header,url=geturl)
    
    logging.info("Successfully extracted the info")
    
    posturl = base_url + endpoint + "/" + oldFeatureProfile["profileType"]
    
    logging.info("Creating the copy")
    
    newFeatureProfileName = input("Enter the new feature profile Name :- ")
    if newFeatureProfileName:
        payload = {"name": newFeatureProfileName,
               "description": response["description"]+"-copy",  
               "fromFeatureProfile": {"copy": oldFeatureProfile["profileId"]}}
    
    else:
        payload = {"name": response["profileName"]+"-copy" + str(random.randint(0,999)),
               "description": response["description"]+"-copy",  
               "fromFeatureProfile": {"copy": oldFeatureProfile["profileId"]}}
    
    newFeatureProfile = api_post_execution (url=posturl, header=api_header, payload=payload)
    
    try:
        if newFeatureProfile["id"] != None:
            logging.info(f" Successfuly copied {feature_profile_name} feature profile and created {payload["name"]}")
            print(f" Successfuly copied {feature_profile_name} feature profile and created {payload["name"]}")
            
    except Exception as e:
        logging.error("Exception occurred inside main function" + str(e))
        
if __name__ == "__main__":
    try:
        
        ip_address = input("Enter your ip_address :- ")
        #ip_address = "vmanage-473102.viptela.net"
        
        port = input("Enter your port :- ")
        #port = "8443"
        
        admin_username = input("Enter your admin_username :- ")
        admin_password = pwinput.pwinput(prompt="Enter your admin_password :- ")
        
        feature_profile_name = input("Enter the Feature Profile Name that needs to be replicated")
        
        logging.info("********************Calling zip function*********************")
        ziptron(ip_address, port, admin_username, admin_password, feature_profile_name )
        logging.info("********************End of zip function*********************")
    except Exception as e:
        logging.error("Exception occurred inside main function" + str(e))
