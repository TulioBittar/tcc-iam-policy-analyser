import json
import re
import requests
import pandas as pd
from csv import DictReader
from bs4 import BeautifulSoup

# ------------------------------------------------------------------------------
# Generate Actions Table
# [ServiceName, ServiceAlias, Action, Description, AccessLevel, Resource]
#-------------------------------------------------------------------------------

# Open JSON file containing Service Alias
# service_alias = json.load('service_alias.json')
with open("service_alias.json", "r") as read_file:
   service_alias = json.load(read_file)

# Open file to write on it
actions_table = open('iam-actions-table.csv', 'w')
# print('ServiceName;Alias;Permission;Action;Description;AccessLevel;Resource')
actions_table.write('ServiceName;Alias;Permission;Action;Description;AccessLevel;Resource' + '\n')

list_of_actions = []
for service in service_alias:
    # open file in read mode
    with open('./actions/'+service+'.csv', 'r') as read_obj:
        # pass the file object to DictReader() to get the DictReader object
        csv_dict_reader = DictReader(read_obj)
        # iterate over each line as a ordered dictionary
        for row in csv_dict_reader:
            # row variable is a dictionary that represents a row in csv
            # print(row)
            srvc_name = service
            srvc_alias = service_alias[service]
            permission = row['Actions']
            action = srvc_alias +':'+ permission
            description = row['Description']
            # replace occurences of ';' to '.' in the description, because ';' is the CSV separator
            description = description.replace(';','.')
            access_level = row['Access level']
            # Get Resource column and check if it is empty or not
            # if empty
            if not row['Resource types (*required)']: resource = False
            # if not empty
            else: resource = True

            if action not in list_of_actions:
                # add to list of actions
                list_of_actions.append(action)
                # print the output
                # print(srvc_name +';'+ srvc_alias +';'+ permission +';'+ action +';'+ description +';'+ access_level +';'+ str(resource))
                # Write on output file
                actions_table.write(srvc_name +';'+ srvc_alias +';'+ permission +';'+ action +';'+ description +';'+ access_level +';'+ str(resource) + '\n')

# Close file
actions_table.close()
