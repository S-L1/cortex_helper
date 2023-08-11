import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

print('''
########################################################################################################################
      
\tThis script adds a date as firstSeen for each of the indicator entries in XSOAR that has been created by the API.
\tIt uses the aliases field to find the record, so make sure that each of the entries from
\tthe configuration file is contained as alias in Cortex only once. 
\tUse the count_records_alias.py script to check.  
\tThis script can run immediately after the new indicators have been created. When indicators are created via API
\tthe firstSeenDate is not set by default. This script gets the date value from the source timestamp field and 
\tcopies it over to the firstSeen field. 
\tIf the lastSeen field is also empty, the timestamp is also copied over to this field.

\t(c) 2023 Sandra Liedtke.
                                                                                                          
########################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")
print('\n')


if cont.upper() in ["Y", "YES"]:
    # get config
    with open('config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

    # api instance
    api_instance = demisto_client.configure(base_url=CONFIG['CortexXSOARAPIConfig']['host'], debug=False, verify_ssl=ssl.CERT_NONE, api_key=CONFIG['CortexXSOARAPIConfig']['api_key'])

    # for each entry
    for indicator_name in CONFIG['entries']:
        try:
            print("Checking " + indicator_name + " in Cortex XSOAR")
            # search current record in Cortex
            indicator_filter = demisto_client.demisto_api.IndicatorFilter()
            indicator_filter.query = 'aliases:"' + indicator_name + '"'
            found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
            if found_indicator.total == 1:
                # indicator exists -> update it
                print("Found indicator " + indicator_name + " in Cortex. Updating with current datetime values...")
                ioc_object = demisto_client.demisto_api.IocObject(found_indicator.ioc_objects[0])
                # Mapping of existing values
                ioc_object.custom_fields = found_indicator.ioc_objects[0]['CustomFields']
                ioc_object.calculated_time = found_indicator.ioc_objects[0]['calculatedTime']
                # correct firstSeen: should be same as the timestamp automatically set when the record was created
                ioc_object.first_seen = found_indicator.ioc_objects[0]['timestamp']
                ioc_object.first_seen_entry_id = found_indicator.ioc_objects[0]['firstSeenEntryID']
                ioc_object.id = found_indicator.ioc_objects[0]['id']
                ioc_object.indicator_type = found_indicator.ioc_objects[0]['indicator_type']
                # check if the lastSeen date is set and update it if required
                ioc_object.last_seen = found_indicator.ioc_objects[0]['timestamp'] if str(found_indicator.ioc_objects[0]['lastSeen'])=="0001-01-01T00:00:00Z" else found_indicator.ioc_objects[0]['lastSeen']
                ioc_object.last_seen_entry_id = found_indicator.ioc_objects[0]['lastSeenEntryID']
                ioc_object.modified = found_indicator.ioc_objects[0]['modified']
                ioc_object.score = found_indicator.ioc_objects[0]['score']
                ioc_object.sort_values = found_indicator.ioc_objects[0]['sortValues']
                ioc_object.timestamp = found_indicator.ioc_objects[0]['timestamp']
                ioc_object.value = found_indicator.ioc_objects[0]['value']
                ioc_object.version = found_indicator.ioc_objects[0]['version']
                # the actual API-Request
                try:
                    api_response = api_instance.indicators_edit(ioc_object=ioc_object)
                except ApiException as e:
                    print("Error while writing " + indicator_name + " to Cortex XSOAR")
                    print(e)
            else:
                # entry is either not available in Cortex or it exists more than once
                print("Skipping indicator with name " + indicator_name + "...")
        # catch exceptions
        except ApiException as e:
            print(e)
            print("Skipping XSOAR Archiving for " + indicator_name)
