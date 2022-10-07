import json
import csv
import re
import requests
import pandas as pd
from csv import DictReader
from bs4 import BeautifulSoup
from datetime import datetime
import os

# --------------------------------------------------------------------------
# EARLY SETUP - CREATE RESULTS FOLDER
# Timestamp used to create directory which will store the results
# format = 2018-11-18 09:32:36.435350
date = datetime.now()
timestamp = str(date)
# Remove Miliseconds
timestamp = timestamp[:-7]
# Replace char : with -
timestamp = timestamp.replace(":", "-")
# Replace char ' '(space) with _
timestamp = timestamp.replace(" ", "_")
# print(timestamp)
# Create directory to store results
directory = "./history/" + timestamp
if not os.path.exists(directory):
    os.makedirs(directory)

# Save IAM Policy into a JSON file in the directory
jsonFilePath = "./history/"+timestamp+"/policy.json"

# --------------------------------------------------------------------------
# Get policy file name
file_name = input("Enter policy file name (with extension): ")
# Open JSON file containing the IAM Policy to be analysed
try:
    with open('./analyse-policy/'+file_name, "r") as read_file:
       iam_policy = json.load(read_file)
except:
    error = True
    msg_error = "JSON Format"
else:
    error = False
    print("JSON is Valid!")

if error:
    # Write error on the file result
    policy_analyser_result = open("./history/"+timestamp+"/policy-analyser-result.csv", "w")
    policy_analyser_result.write("ERROR at "+ msg_error +": IAM Policy is invalid.\nPlease, access the AWS Console and validate your IAM Policy at the link below:\n\n\thttps://us-east-1.console.aws.amazon.com/iam/home#/policies$new?step=edit\n")
    policy_analyser_result.close()
    # Print error and finish program
    print("\n\nERROR at "+ msg_error +": IAM Policy is invalid.\nPlease, access the AWS Console and validate your IAM Policy at the link below:\n\n\thttps://us-east-1.console.aws.amazon.com/iam/home#/policies$new?step=edit\n")

# Proceed with the analysis
else:
    # Open files on read mode
    actions_critical = open("./actions-table-generator/iam-actions-critical.txt", "r")

    # Open JSON file containing Service Alias
    with open("./actions-table-generator/service_alias.json", "r") as read_file_alias:
       service_alias = json.load(read_file_alias)
    # Open JSON file containing Service URLs
    with open("./actions-table-generator/service_urls.json", "r") as read_file_url:
       service_urls = json.load(read_file_url)

    # Remove NewLine character at the end of each line in the iam-actions-critical.txt file
    list_temp = actions_critical.readlines()
    actions_critical_list = []
    for x in list_temp:
        actions_critical_list.append(x.replace("\n", ""))
    # print(actions_critical_list)



    # Error Treatment. Verify if headers are valid
    try:
        stmt_stmt = iam_policy['Statement']
        stmt_Version = iam_policy['Version']
    except:
        error = True
        stmt_error = "Headers"
    else:
        error = False
        print("Headers are Valid!")

    if error:
        # Write error on the file result
        policy_analyser_result = open("./history/"+timestamp+"/policy-analyser-result.csv", "w")
        policy_analyser_result.write("ERROR at "+ stmt_error +": IAM Policy is invalid.\nPlease, access the AWS Console and validate your IAM Policy at the link below:\n\n\thttps://us-east-1.console.aws.amazon.com/iam/home#/policies$new?step=edit\n")
        policy_analyser_result.close()
        # Print error and finish program
        print("\n\nERROR at "+ stmt_error +": IAM Policy is invalid.\nPlease, access the AWS Console and validate your IAM Policy at the link below:\n\n\thttps://us-east-1.console.aws.amazon.com/iam/home#/policies$new?step=edit\n")

    # Proceed with the analysis
    else:
        # Create CSV File to store the critical actions found in the IAM policy
        policy_analyser_result = open("./history/"+timestamp+"/policy-analyser-result.csv", "w")
        policy_analyser_result.write("StatementNumber;Action;AccessLevel;Resource;Description;Documentation"+'\n')
        print("StatementNumber;Action;AccessLevel;Resource;Description;Documentation")

        print("Critical Actions found in the IAM Policy:")
        # stmt_index = 0
        # Open statements
        for i,statement in enumerate(iam_policy['Statement'], start=1):
            # print("Statement "+ str(i))
            # Error Treatment. Verify if statement is valid
            # if the statement doesn`t have the necessary fields, print error and finish program.
            try:
                stmt_action = statement['Action']
                stmt_effect = statement['Effect']
                stmt_effect = statement['Resource']
            except:
                error = True
                stmt_error = "Statement "+str(i)
                break
            else:
                error = False
                print("Statement "+str(i)+" is Valid!")
            # print(str(statement['Action']))
            # Get Statement Actions
            # if the Action section has only one action, transform the string in a list
            #
            if type(statement['Action']) != list:
                stmt_actions = []
                stmt_actions.append(statement['Action'])
            else:
                stmt_actions = statement['Action']
            for action in stmt_actions:
                # print(action)
                # Error Treatment. Verify if Action is valid
                # Split the action between Service and Permission
                try:
                    action_split = action.split(":")
                    action_service = action_split[0]
                    action_permission = action_split[1]
                except:
                    error = True
                    stmt_error = "Statement "+str(i)
                    break
                else:
                    # If any of the variables is empty, the action has an error
                    if not action_service or not action_permission:
                        error = True
                        stmt_error = "Statement "+str(i)
                        break

                # Prepare regex for action_permission
                # se tiver * no início, add ^. no início
                if re.match("\*",action_permission):
                    action_permission = "^." + action_permission
                # se tiver char no início, add ^ no início
                if re.match("^[a-zA-Z]",action_permission):
                    action_permission = "^" + action_permission
                # se tiver * no final, faz nada
                # se tiver char no final, add $ no final
                if re.match("^.*[a-zA-Z]$",action_permission):
                    action_permission = action_permission + "$"

                # print("Action Regex to be verified: " + action_permission)

                for critical_action in actions_critical_list:
                    # Ṣplit Critical Action between service and permission
                    critical_action_split = critical_action.split(":")
                    critical_action_service = critical_action_split[0]
                    critical_action_permission = critical_action_split[1]

                    # Analyse if action is critical or not
                    if action_service == critical_action_service:
                        # regex = re.search("^.*Object$", critical_action_permission)
                        regex = re.search(action_permission, critical_action_permission)
                        # if action_permission in critical_action_permission:
                        if regex:
                            # Found a Critical Action
                            # print('\t' + critical_action)
                            # open actions-table in read mode to get details about the action
                            with open("./actions-table-generator/iam-actions-table.csv", "r") as read_obj:
                                # pass the file object to DictReader() to get the DictReader object
                                csv_dict_reader = DictReader(read_obj,delimiter=";")
                                # iterate over each line as a ordered dictionary
                                for row in csv_dict_reader:
                                    # print(str(row))
                                    if row['Action'] == critical_action:
                                        access_level = row['AccessLevel']
                                        resource = row['Resource']
                                        description = row['Description']

                            # Get Service Web Documentation URL
                            for name in service_alias:
                                if service_alias[name] == critical_action_service:
                                    # Get Service Full Name
                                    service_name = name
                                    # Get Service URL
                                    for s_name in service_urls:
                                        if s_name == service_name:
                                            service_url = service_urls[s_name]

                            print(str(i) +';'+ critical_action +';'+ access_level +';'+ resource +';'+ description +';'+ service_url)
                            policy_analyser_result.write(str(i) +';'+ critical_action +';'+ access_level +';'+ resource +';'+ description +';'+ service_url + '\n')

            # Check if there was an error while getting the Action
            if error:
                break

        # Close file
        actions_critical.close()
        policy_analyser_result.close()

        # Transform Results from CSV file to JSON File, for better visualization
        csvFilePath = "./history/"+timestamp+"/policy-analyser-result.csv"
        jsonFilePath = "./history/"+timestamp+"/policy-analyser-result.json"
        # read csv file and add to csv_data
        csv_data = []
        with open(csvFilePath) as csvFile:
            csvReader = csv.DictReader(csvFile,delimiter=";")
            for row in csvReader:
                csv_data.append(row)

        with open(jsonFilePath, 'w') as jsonFile:
            jsonFile.write(json.dumps( csv_data, indent=4, separators=(',', ':') ))
