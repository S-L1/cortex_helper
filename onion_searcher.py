import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException
import requests

print('''
########################################################################################################################
                                                                                                           
\tThis script adds the onion links to the threat actor groups if the link is known to ransomware.live.  
\tIt replaces the existing url with those from the website. 
\n\t!! Data will be overwritten in Cortex for all ransomware threat actors and malware which can be found
\ton ransomware.live.                       
                                                                                                           
\t(c) 2023 Sandra Liedtke.                                                                                 
                                                                                                          
########################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")


if cont.upper() in ["Y", "YES"]:
    # get config
    with open('config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

    # technical name of the field where the onion urls should be added
    url_field_name = "note"
    continue_ = input("Found Onion URLs will be entered to the field custom_fields." + url_field_name + "\n\nTHIS WILL OVERWRITE EXISTING VALUES IN CORTEX XSOAR!\nDo you want to continue and replace existing data (Y/n)? ")

    if continue_.upper() in ["Y", "YES"]:
        api_instance = demisto_client.configure(base_url=CONFIG['archiving']['CortexXSOARAPIConfig']['host'], debug=False, verify_ssl=ssl.CERT_NONE, api_key=CONFIG['archiving']['CortexXSOARAPIConfig']['api_key'])
        try:
            # send get request to ransomware.live API
            print("Getting known groups from ransomware.live...")
            response = requests.get("https://api.ransomware.live/groups", headers={"accept": "application/json"})
        except Exception as e:
            print('Error accessing webpage. Error Message: ', str(e))
            exit()

        # response in json
        data = json.loads(response.text)
        # for each archivedData entry and for each group known to ransomware.live
        for indicator_name in CONFIG['archiving']['archivedData']:
            for row in data:
                if indicator_name.upper() == row['name'].upper():
                    try:
                        # search current record in Cortex
                        indicator_filter = demisto_client.demisto_api.IndicatorFilter()
                        indicator_filter.query = 'aliases:"' + row['name'] + '"'
                        found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
                        # if the record is found in Cortex, overwrite it
                        if found_indicator.total == 1:
                            print("\n\nFound " + indicator_name.upper() + " in ransomware.live row " + row['name'].upper())
                            print("The record will be overwritten in Cortex")
                            # indicator exists -> update it
                            ioc_object = demisto_client.demisto_api.IocObject(found_indicator.ioc_objects[0])
                            # Mapping of existing values
                            ioc_object.custom_fields = found_indicator.ioc_objects[0]['CustomFields']
                            ioc_object.calculated_time = found_indicator.ioc_objects[0]['calculatedTime']
                            ioc_object.first_seen = found_indicator.ioc_objects[0]['firstSeen']
                            ioc_object.first_seen_entry_id = found_indicator.ioc_objects[0]['firstSeenEntryID']
                            ioc_object.id = found_indicator.ioc_objects[0]['id']
                            ioc_object.indicator_type = found_indicator.ioc_objects[0]['indicator_type']
                            ioc_object.last_seen = found_indicator.ioc_objects[0]['lastSeen']
                            ioc_object.last_seen_entry_id = found_indicator.ioc_objects[0]['lastSeenEntryID']
                            ioc_object.modified = found_indicator.ioc_objects[0]['modified']
                            ioc_object.score = found_indicator.ioc_objects[0]['score']
                            ioc_object.sort_values = found_indicator.ioc_objects[0]['sortValues']
                            ioc_object.timestamp = found_indicator.ioc_objects[0]['timestamp']
                            ioc_object.value = found_indicator.ioc_objects[0]['value']
                            ioc_object.version = found_indicator.ioc_objects[0]['version']
                            onions = ''
                            # all onion links for the respective group
                            for entry in row['locations']:
                                status = "active" if entry['available'] == True else "inactive"
                                onions += entry['fqdn'] + ",\t" + status + "\n"

                            ioc_object.custom_fields['note'] = onions
                            # the actual API-Request
                            try:
                                api_response = api_instance.indicators_edit(ioc_object=ioc_object)
                                print("Updated " + indicator_name + " in Cortex XSOAR")
                            except ApiException as e:
                                print("Error while writing " + indicator_name + " to Cortex XSOAR")
                                print(e)
                    # catch exceptions
                    except ApiException as e:
                        print(e)
                        print("Skipping XSOAR Archiving for " + indicator_name)