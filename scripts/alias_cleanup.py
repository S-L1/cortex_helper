import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

print('''
########################################################################################################################
                                                                                                           
\tThis script removes the blanks from each entry in the alias field for all indicator records.                                  
                                                                                                           
\t(c) 2024 Sandra Liedtke.                                                                                 
                                                                                                          
########################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")

if cont.upper() in ["Y", "YES"]:
    # own function, so it can be called recursive
    def clean_aliases():
        clean_aliases = []
        # for each alias remove the blanks and write the cleaned version to the list
        for alias in found_indicator.ioc_objects[0]['CustomFields']['aliases']:
            cleaned_alias = alias.replace(' ', '')
            clean_aliases.append(cleaned_alias)
        return clean_aliases


    # get config
    with open('../config/config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

    # api instance
    api_instance = demisto_client.configure(base_url=CONFIG['archiving']['CortexXSOARAPIConfig']['host'], debug=False,
                                            verify_ssl=ssl.CERT_NONE,
                                            api_key=CONFIG['archiving']['CortexXSOARAPIConfig']['api_key'])

    # call mitre webpage
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36'
    headers = {'User-Agent': user_agent}

    # for each archivedData entry
    for indicator_name in CONFIG['archiving']['archivedData']:
        # match the name in the second column
        try:
            # search current record in Cortex
            indicator_filter = demisto_client.demisto_api.IndicatorFilter()
            indicator_filter.query = 'aliases:"' + indicator_name + '"'
            found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
            # if the record exists in Cortex re-verify before updating it
            if found_indicator.total == 1:
                print("\n\nFound " + indicator_name.upper() + " in Cortex. Starting Update of Alias")
                ioc_object = demisto_client.demisto_api.IocObject(found_indicator.ioc_objects[0])
                # Mapping of existing values
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

                # Clean aliases
                ioc_object.custom_fields['aliases'] = []
                cleaned_aliases = clean_aliases()
                # other custom fields should not be changed
                ioc_object.custom_fields = found_indicator.ioc_objects[0]['CustomFields']
                # overwrite aliases with cleaned values
                ioc_object.custom_fields['aliases'] = cleaned_aliases

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
