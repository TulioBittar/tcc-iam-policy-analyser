import json
import re
import requests
import pandas as pd
from csv import DictReader
from bs4 import BeautifulSoup

# ------------------------------------------------------------------------------
# Get HTML page "Actions, resources, and condition keys for AWS services"
#-------------------------------------------------------------------------------
url_all_services = 'https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html#actions_table'
html = requests.get(url_all_services).content
soup = BeautifulSoup(html, 'html.parser')
# print(soup.prettify())

# ------------------------------------------------------------------------------
# Get AWS Service name and URL
#-------------------------------------------------------------------------------
# Dictionary to save AWS Service URLs
service_urls = {}
# Dictionary to save AWS Service alias
service_alias = {}

# Get AWS Service URLs
for link in soup.find_all('a'):
    # print(link.get('href'))
    # Extract Service Name
    service_name = re.findall('>(.+?)<', str(link))
    service_name = re.sub('\[|\'|\]', '', str(service_name))
    # print(service_name)

    # save the sufix
    suffix = link.get('href')
    # check if the suffix
    if './list' in suffix:
        # Remove the "." from the suffix, because it is not a part of the URL
        suffix = suffix[1:]
        # Concatenate the prefix with the suffix
        full_url = "https://docs.aws.amazon.com/service-authorization/latest/reference" + suffix

        # Save full_url to dictionary
        service_urls[service_name] = full_url

# # After getting all URLs in the Dictionary, save it to a JSON file
with open('service_urls.json', 'w') as outfile:
    json.dump(service_urls, outfile, indent=4)


# ------------------------------------------------------------------------------
# Get actions and alias for each AWS service, directly from the URLs collected
#-------------------------------------------------------------------------------
# for i in d:
#     print i, d[i]

# print(service)
for service in service_urls:
    # Get URL content
    html_service = requests.get(service_urls[service]).content

    # Get All Tables from page
    df_list = pd.read_html(html_service)
    # get first table [0] of the webpage
    df = df_list[0]
    # print(df)
    # Save actions table to CSV file
    df.to_csv('./actions/'+service+'.csv')

    # Get Service Alias
    soup_alias = BeautifulSoup(html_service, 'html.parser')
    # Get class code
    alias = soup_alias.find_all("code", {"class": "code"})
    # print(alias[0])
    # Conversion. We only need the first apparison of 'code', that`s the reason of alias[0]
    alias = re.findall('>(.+?)<', str(alias[0]))
    alias = re.sub('\[|\'|\]', '', str(alias))
    print(alias +' : '+ service)
    # Save to dictionary
    service_alias[service] = alias

with open('service_alias.json', 'w') as outfile_2:
    json.dump(service_alias, outfile_2, indent=4)
