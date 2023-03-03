#!/usr/bin/python3
from flask import Flask, render_template
import ssl
import yaml
from cryptography import x509
import datetime
import requests

app = Flask(__name__)
config_file= "/etc/certtracker.yml"
alt_ssl = "/etc/ssl/certs/rooty.cer"

#Load Config from File
def var_load(config_file):
    with open(config_file, "r") as stream:
        try:
            settings = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return settings

#Checks Web Servers/SSL
def verify_site_func(url, alt_ssl_chk):
    try:
        site_error = ""
        if alt_ssl_chk == True:
            site_result = requests.get(url, timeout=20, verify=alt_ssl)
            print("Has Custom SSL")
        else:
            site_result = requests.get(url, timeout=20, verify=True)
            print("Has 3rd Party SSL")
        print(site_result)
        #print(site_result.status_code) #Testing function
    except requests.exceptions.SSLError as err1:
        site_error = ("SSL Certificate Expired", "Down")
        return site_error
    except requests.exceptions.Timeout as err2:
        site_error = ("Timed Out", "Down")
        return site_error
    except requests.exceptions.ConnectionError as err3:
        site_error = ("Other", "Down")
        return site_error
    if(site_result.status_code >= 400): 
        site_error = ("Application or Server Issue", "Down")
        return site_error
    if(site_error==""):
        return ("", "Up") 


def check_cert(site):
    today_date = datetime.date.today()
    #Create Tuple with Site Name and Port #
    certificate = ssl.get_server_certificate((site, 443))
    #print(certificate)
    #Convert Certificate String to Bytes
    cert_info = x509.load_pem_x509_certificate(bytes(certificate, 'utf-8'))
    #print(cert_info.not_valid_after)
    #Get Expiry Date
    expiry_date = cert_info.not_valid_after
    #Compare Expiry Date with Todays Date
    time_left = expiry_date.date() - today_date
    #Return time left on certificate in days
    #print(int(time_left.days))
    return (int(time_left.days))

def ssl_lookup(settings):
    info_array = []
    for item in settings:
        site = item["server"]
        alt_ssl_chk = item["alt_ssl"]
        url = "https://" + site +"/"
        site_status = verify_site_func(url, alt_ssl_chk)
        if site_status[1] == "Up":
            cert_days_left = check_cert(site)
        else:
            cert_days_left = "N/A"
        gathered_info = dict(url=url, internal_cert=alt_ssl_chk, status_desc=site_status[0], status=site_status[1], time_left=cert_days_left)
        #print(gathered_info)
        info_array.append(gathered_info)
    #print(info_array)
    return info_array



@app.route('/')  # create a route for / - just to test server is up.
def index():
    settings = var_load(config_file)
    site_info = ssl_lookup(settings)
    return render_template('app_core.html',sites=site_info)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=5000)

