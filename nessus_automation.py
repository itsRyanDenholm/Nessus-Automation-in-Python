# Ryan Denholm
# Nessus Automation Script
# CMP304 - Scripting
# 18/04/2024

# Used for requesting, downloading and editing reports
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import time 
import pandas as pd 

# Imports for Selenium - used for creating a scan

from selenium import webdriver
import selenium.webdriver.support.ui as ui
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import os

# Nessus Essentials Service
url = "https://192.168.0.241:8834"


# Admin Creds
username = "ryan"
password = "ryan"

# Authentication
# Header for authentication, includes access and secret key
headers_auth = {
    "accept": "application/json",
    "content-type": "application/json",
    # API keys obtained through Nessus Interface - need to be regenerated each time nessus is started 
    "X-ApiKeys": "accessKey=3c6696c99bfba2562e159e52e8e3e45603f8b5d4efa4c27f32ad9077bbb52364;secretKey=1c08fb571647a809ca6fc0692405e122496aa17e83043de0628869f713fd55b3"
}

# Creating payload with login credentials
payload_auth = {"username": username, "password": password}

# Authenticates the session with login credentials and APIKeys
response_login = requests.post(url+"/session", json=payload_auth, headers=headers_auth, verify=False)

#for testing - DELETE
#print(response_login.text)

# Create header with cookie for further use

header_perm = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-Cookie": "token="+ response_login.json()["token"]
}

#This doesnt work. 
#response_user_list = requests.get(url+"/users", header_perm, verify=False)
#print(response_user_list.text)

# List Scan Request & Validates 
# Requesting a list of all scans created
response_scan = requests.get(url+"/scans", headers=header_perm, verify=False)

# for testing - DELETE
#print(response_scan.text)

# Parse through scan list, creates a dictionary containing scan names and UUIDs
scan_info = {}
for scan in response_scan.json()["scans"]:
    scan_info[scan["name"]] = {"uuid": scan["uuid"], "id": scan["id"]}

# !!!Input IF statement based on if user wants to download an existing scan or create a new one
# Requires input == 1 or == 2, this will decide if download or new scan
# 
user_input = input("Enter 1 to download an existing scan or 2 to create a new one: ")

if user_input == "1":
    print("You chose to download an existing scan")

    # User input for scan name // CASE SENSITIVE
    scan_name = input("Please enter the name of the scan you are looking to access: ")

    # Validates existance of scan 
    if scan_name in scan_info:
        print("Scan Found!")
    else:
        print("Unable to find scan: "+scan_name+". Reminder, case sensitive!")


    # Obtain Scan Details
    # Saves scan ID to its own variable, easier for future requests
    scan_id = scan_info[scan_name]["id"]

    # Will request the details of provided scan ID
    response_details = requests.get(url+"/scans"+"/"+str(scan_id), headers=header_perm, verify=False)

    # TESTING - DELETE
    #print(response_details.text)


    # Export Scan Results
    # Basic Settings
    export_format = "csv"  # Required, Example format, can be HTML, Nessus, CSV, pdf - currently PDF is not working. 
    chapters = ["vuln_hosts_summary", "vuln_by_host", "vuln_by_plugin"]  # Example chapters, change as needed
    password = "your_password"  # Optional password for encryption, change as needed
    template_id = True # Required

    # Payload for export request
    payload_export = {
        "format": export_format,
        "template_id" : template_id,
        "chapters": chapters,
        "password": password
    }

    # Creating export url based on scan id
    url_export = "https://192.168.0.241:8834/scans/"+str(scan_id)+"/export"

    # Send export request
    response_export = requests.post(url_export, json=payload_export, headers=header_perm, verify=False)

    # Check if export request was successful
    if response_export.status_code == 200:
        # Extract "file" from JSON response
        response_json = response_export.json()
        file_url = response_json.get("file")
        
        if file_url:
            print("File URL:", file_url)
        else:
            print("File URL not found in the response.")
    else:
        print("Export request failed with status code:", response_export.status_code)

    print("Preparing Report, please be patient. (5 Seconds)")
    time.sleep(5)

    # Create URL for download
    url_download = "https://192.168.0.241:8834/scans/" + str(scan_id) + "/export/" + str(file_url) + "/download"

    # Initiate download
    response_download = requests.get(url_download, headers=header_perm, verify=False)

    # Check if download request was successful
    if response_download.status_code == 200:
        # Get the file content
        file_content = response_download.content
        
        # Define the file path where you want to save the downloaded file
        file_path = r"C:\Users\ryant\Documents\Scripting\Report "+scan_name+"."+export_format  # You can change the file name and path as needed
        
        # Write the content to a local file
        with open(file_path, "wb") as file:
            file.write(file_content)
            
        print("Downloaded file saved successfully at:", file_path)
    else:
        print("Download request failed with status code:", response_download.status_code)
    
    # Read the downloaded CSV file
    df = pd.read_csv(file_path)

    # Select only the required columns
    selected_columns = ["CVSS v2.0 Base Score", "Host", "Protocol", "Port", "Name"]
    df_selected = df[selected_columns]

    # Sort the data by "CVSS v2.0" column from High to Low
    df_sorted = df_selected.sort_values(by="CVSS v2.0 Base Score", ascending=False)

    # Define the file path for the sorted CSV file
    sorted_file_path = r"C:\Users\ryant\Documents\Scripting\Sorted_Report_" + scan_name + ".csv"

    # Save the sorted data to a new CSV file
    df_sorted.to_csv(sorted_file_path, index=False)

    print("Sorted CSV file saved successfully at:", sorted_file_path)




elif user_input == "2":
    
    print("You chose to create a new scan")

    # Specify the path to the Chrome driver executable
    chrome_driver_path = r"C:\Users\ryant\Documents\Scripting\chromedriver.exe"  

    # Initialize Chrome WebDriver with the specified driver path
    service = Service(chrome_driver_path)
    service.start()

    # Allows for chrome webdriver options
    chrome_options = webdriver.ChromeOptions()

    # Specify the path to the Chrome browser executable
    chrome_binary_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    # Adds Chrome binary path to chrome options
    chrome_options.binary_location = chrome_binary_path

    # Ignores cert, allows for automation past the chrome warning
    chrome_options.add_argument('--ignore-certificate-errors')

    # Pass the Chrome options to the Chrome driver
    driver = webdriver.Chrome(service=service, options=chrome_options)

    # Connects to Nessus URL
    driver.get("https://192.168.0.241:8834/")
    wait = ui.WebDriverWait(driver, 30)

    # TESTING - DELETE
    print(driver.page_source)

    # Waits until input 1 field appears.
    username_input = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/div/form/div[1]/input")))
    # sends username variable to username_input
    username_input.send_keys(username)

    # Waits until input field 2 appears.
    password_input = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/div/form/div[2]/input")))
    # sends password variable to password_input
    password_input.send_keys(password)

    # Finds and clicks the login button.
    log_in = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/div/form/button")))
    log_in.click()

    ## LOGIN WORKS!!

    time.sleep(2)

    # Select new scan tab
    new_scan = driver.find_element(By.ID, "new-scan")
    new_scan.click()
    time.sleep(2)

    # Select advanced scan
    advanced_scan = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/section[3]/section[3]/section/div[1]/div[2]/div[2]/a[2]")))
    advanced_scan.click()

    time.sleep(2)

    ## SCAN SETTINGS
    # assembling date and time
    time_asmb = time.asctime(time.localtime(time.time())).split()
    # Create scan name based on date and time of accessing "advanced scan"
    scan_name = time_asmb[2]+'_'+time_asmb[1]+'_'+time_asmb[4]+'_'+time_asmb[3]
    set_scan_name = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/section[3]/section[3]/section/form/div[1]/div/div/div[1]/section/div[1]/div[1]/div[1]/div[1]/div/input")))
    set_scan_name.send_keys(scan_name)

    time.sleep(1)

    # Create a description
    upload_descp = driver.find_element(By.XPATH, "/html/body/section[3]/section[3]/section/form/div[1]/div/div/div[1]/section/div[1]/div[1]/div[1]/div[2]/div/textarea")
    description = "This is a scan made by Nessus Automated Script"
    upload_descp.send_keys(description)

    time.sleep(1)

    # Set targets, in this case 192.168.0.1/24
    set_targets = driver.find_element(By.XPATH, "/html/body/section[3]/section[3]/section/form/div[1]/div/div/div[1]/section/div[1]/div[1]/div[1]/div[5]/div/textarea")
    target = "192.168.0.1/24" # CHANGE FOR DIFFERENT TARGETS
    set_targets.send_keys(target)

    time.sleep(2)

    # Click the "save" button
    save_settings = wait.until(EC.visibility_of_element_located((By.XPATH, "/html/body/section[3]/section[3]/section/form/div[2]/span"))).click()

    time.sleep(5)

    ## LAUNCH SCAN
    # Create XPath seperately so it will dynamically generate for the newest scan created
    launch_xpath = '/html/body/section[3]/section[3]/section/div[2]/table/tbody/tr[@data-name={}]/td[9]/i'.format(scan_name)
    print(launch_xpath)
    launch_scan = wait.until(EC.visibility_of_element_located((By.XPATH, str(launch_xpath))))
    time.sleep(2)
    launch_scan.click()
    

else:
    print("Invalid Input, exiting.")
    exit



