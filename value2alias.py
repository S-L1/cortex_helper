import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

print('''
########################################################################################################################
                                                                                                           
\tThis script adds for each value in Cortex the data from the value field also into the aliases field if it is not 
\tyet there.
                                                                                                           
\t(c) 2023 Sandra Liedtke.                                                                                 
                                                                                                          
########################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")
print('\n')


if cont.upper() in ["Y", "YES"]:
    # own function, so it can be called multiple times without redundant code
    def check_aliases():
        is_alias = False
        for alias in ioc_object.custom_fields['aliases']:
            if found_indicator.ioc_objects[0]['value'] == alias:
                is_alias = True
        if not is_alias:
            ioc_object.custom_fields['aliases'].append(found_indicator.ioc_objects[0]['value'])


    # get config
    with open('config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

    # api instance
    api_instance = demisto_client.configure(base_url=CONFIG['CortexXSOARAPIConfig']['host'], debug=False, verify_ssl=ssl.CERT_NONE, api_key=CONFIG['CortexXSOARAPIConfig']['api_key'])

    # call mitre webpage
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36'
    headers = {'User-Agent': user_agent}

    # for each entry
    for indicator_name in CONFIG['entries']:
        try:
            # search current record in Cortex by value
            indicator_filter = demisto_client.demisto_api.IndicatorFilter()
            indicator_filter.query = 'value:"' + indicator_name + '"'
            found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
            if found_indicator.total == 1:
                # indicator exists -> update it
                print("\n\nFound " + indicator_name.upper() + " in Cortex. Starting Update of Alias")
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
                # Update aliases with value
                try:
                    check_aliases()
                except:
                    # field does not exist - create it first
                    ioc_object.custom_fields['aliases'] = []
                    check_aliases()
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
