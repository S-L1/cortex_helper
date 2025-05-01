import json
import ssl
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

print('''
########################################################################################################################
                                                                                                           
\tThis script can be used to batch-update the Cortex XSOAR indicators that are retrieved with the given filter query.
\tMake sure to verify the records and fields to be updated where a TODO is specified in the code!
\n\t!! Existing data in Cortex might be overwritten for a large number of records !!                                        
                                                                                                           
\t(c) 2025 Sandra Liedtke.                                                                                 
                                                                                                          
########################################################################################################################
''')
cont = input("Want to continue (Yes/No)? ")

if cont.upper() in ["Y", "YES"]:

    # get config
    with open('../config/config.json', 'r') as config_file:
        CONFIG = json.load(config_file)

   # api instance
    api_instance = demisto_client.configure(base_url=CONFIG['profiling']['CortexXSOARAPIConfig']['host'],
                                            debug=False,
                                            verify_ssl=ssl.CERT_NONE,
                                            api_key=CONFIG['profiling']['CortexXSOARAPIConfig']['api_key'])
    try:
        # set filter
        indicator_filter = demisto_client.demisto_api.IndicatorFilter()

        # TODO: Adjust filter query - All records displayed with this query will be changed
        indicator_filter.query = 'type:Malware'

        found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)
        i = 0

        # update each of the found indicators
        while i < found_indicator.total:
            ioc_object = demisto_client.demisto_api.IocObject(found_indicator.ioc_objects[i])
            # Mapping of existing values without any change
            ioc_object.custom_fields = found_indicator.ioc_objects[i]['CustomFields']
            ioc_object.calculated_time = found_indicator.ioc_objects[i]['calculatedTime']
            ioc_object.first_seen = found_indicator.ioc_objects[i]['firstSeen']
            ioc_object.first_seen_entry_id = found_indicator.ioc_objects[i]['firstSeenEntryID']
            ioc_object.id = found_indicator.ioc_objects[i]['id']
            ioc_object.indicator_type = found_indicator.ioc_objects[i]['indicator_type']
            ioc_object.last_seen = found_indicator.ioc_objects[i]['lastSeen']
            ioc_object.last_seen_entry_id = found_indicator.ioc_objects[i]['lastSeenEntryID']
            ioc_object.modified = found_indicator.ioc_objects[i]['modified']
            ioc_object.score = found_indicator.ioc_objects[i]['score']
            ioc_object.sort_values = found_indicator.ioc_objects[i]['sortValues']
            ioc_object.timestamp = found_indicator.ioc_objects[i]['timestamp']
            ioc_object.value = found_indicator.ioc_objects[i]['value']
            ioc_object.version = found_indicator.ioc_objects[i]['version']

            # TODO: Specify field and value to be updated during batch-update
            val= ""
            ioc_object.custom_fields[''] = val

            # the actual API-Request
            try:
                api_response = api_instance.indicators_edit(ioc_object=ioc_object)
                print("Updated indicator " + found_indicator.ioc_objects[i]['value'])
                # get next record
                i += 1
            except ApiException as e:
                print("Error while writing to Cortex XSOAR. Cancelling execution for indicator "  + found_indicator.ioc_objects[i]['value'])
                print(e)
                i += 1
                continue

    except Exception as e:
        print("Error while execution. Cancelling...")
        print(e)