import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

print('''
##############################################################################################################################
                                                                                                           
\tThis script prints for each entry in the config file how many records are available in Cortex if there are more than one. 
\tIt uses the aliases field to find the records. The script is designed to find any duplicates. 
\tIf a value appears more than once, the name given in the value field will be printed with the number indicating how often
\tit was found.          
                                                                                                           
\t(c) 2023 Sandra Liedtke.                                                                                 
                                                                                                          
#############################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")
print('\n')


if cont.upper() in ["Y", "YES"]:
    # get config
    with open('../config/config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

    # api instance
    api_instance = demisto_client.configure(base_url=CONFIG['CortexXSOARAPIConfig']['host'], debug=False, verify_ssl=ssl.CERT_NONE, api_key=CONFIG['CortexXSOARAPIConfig']['api_key'])

    # variables for the statistics
    result = ""
    i_conf = 0
    i_cortex = 0
    i_duplicates = 0
    # for each entry check how often it exists in Cortex. Print the value if it exists more than once
    for indicator_name in CONFIG['entries']:
        i_conf += 1
        try:
            # search current record in Cortex and add it to duplicates list if more than one record appears
            indicator_filter = demisto_client.demisto_api.IndicatorFilter()
            indicator_filter.query = 'aliases:"' + indicator_name + '"'
            found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
            if found_indicator.total > 0:
                i_cortex += 1
                if found_indicator.total > 1:
                    i_duplicates += 1
                    result += "Found " + indicator_name + " in Cortex: " + str(found_indicator.total) + " times\n"
        # catch exceptions
        except ApiException as e:
            print(e)
            print("Cannot count. Aborting...")
    if result == "":
        result = "Did not find any duplicate aliases"

    # the statistics
    result += "\n\nSTATISTICS:\nChecked " + str(i_conf) + " indicators from CONFIG File. " + str(i_cortex) + " were found in Cortex XSOAR of which " + str(i_duplicates) + " were found to be duplicates.\n\n"
    print(result)
