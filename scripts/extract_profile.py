import json
import ssl
import os
from datetime import datetime
import time
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException
from odf.opendocument import OpenDocumentText
from odf.style import *
from odf.text import *

print('''
#############################################################################################################################

\tThis script extracts the indicator specified in the input field and writes the profile information into a word document.
\tIt uses the aliases field to find the records.
\tThe script can be used to generate a report about a specific indicator.

\t(c) 2025 Sandra Liedtke.                                                                                 

#############################################################################################################################
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

        # specify the indicator for which the report should be generated
        indicator_profile = input("Enter alias for profile to extract: ")

        try:
            # search profile in Cortex
            indicator_filter = demisto_client.demisto_api.IndicatorFilter()
            indicator_filter.query = 'aliases:"' + indicator_profile + '"'
            found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)

            if found_indicator.total == 0:
                print("The requested indicator could not be found. Skipping report generation...")
                exit()
            else:
                # dictionary for the basic profile fields with key = field label and value = field value
                profile_fields = {"Names": str(found_indicator.ioc_objects[0]['CustomFields']['aliases']).replace("'", "").replace("[", "").replace("]", ""),
                                  "Type": found_indicator.ioc_objects[0]['indicator_type'] + "\n",
                                  "Time of Profiling": time.strftime("%A, %d. %B %Y, %H:%M h", time.strptime(found_indicator.ioc_objects[0]['firstSeen'].split(".")[0], "%Y-%m-%dT%H:%M:%S")),
                                  "Last Seen in News": time.strftime("%A, %d. %B %Y, %H:%M h", time.strptime(found_indicator.ioc_objects[0]['lastSeen'].split(".")[0], "%Y-%m-%dT%H:%M:%S")) + "\n",
                                  "Description": "\n" + found_indicator.ioc_objects[0]['CustomFields']['description'] + "\n" if 'description' in found_indicator.ioc_objects[0]['CustomFields'] else "-\n",
                                  "Weblinks": found_indicator.ioc_objects[0]['CustomFields']['note'] if 'note' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                                  }

                # additional fields per indicator type
                if found_indicator.ioc_objects[0]['indicator_type'] == "Malware" or found_indicator.ioc_objects[0]['indicator_type'] == "Botnet":
                    profile_fields["Operating Systems"] = str(found_indicator.ioc_objects[0]['CustomFields']['operatingsystemrefs']).replace("'", "").replace("[", "").replace("]", "") if 'operatingsystemrefs' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Implementation Language"] = str(found_indicator.ioc_objects[0]['CustomFields']['implementationlanguages']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'implementationlanguages' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Kill Chain Phases"] = str(found_indicator.ioc_objects[0]['CustomFields']['killchainphases']).replace("'", "").replace("[", "").replace("]", "") if 'killchainphases' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["MITRE ATT&CK Techniques"] = str(found_indicator.ioc_objects[0]['CustomFields']['mitreattacktechnique']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'mitreattacktechnique' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Malware Type"] = found_indicator.ioc_objects[0]['CustomFields']['malwaretype'] if 'malwaretype' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Virus Total"] = found_indicator.ioc_objects[0]['CustomFields']['url'] if 'url' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["MD5"] = found_indicator.ioc_objects[0]['CustomFields']['md5'] if 'md5' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["SHA1"] = found_indicator.ioc_objects[0]['CustomFields']['sha1'] if 'sha1' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["SHA256"] = found_indicator.ioc_objects[0]['CustomFields']['sha256'] if 'sha256' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"

                elif found_indicator.ioc_objects[0]['indicator_type'] == "Ransomware":
                    profile_fields["Kill Chain Phases"] = str(found_indicator.ioc_objects[0]['CustomFields']['killchainphases']).replace("'", "").replace("[", "").replace("]", "") if 'killchainphases' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["MITRE ATT&CK Techniques"] = str(found_indicator.ioc_objects[0]['CustomFields']['mitreattacktechnique']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'mitreattacktechnique' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Operating Systems"] = str(found_indicator.ioc_objects[0]['CustomFields']['operatingsystemrefs']).replace("'", "").replace("[", "").replace("]", "") if 'operatingsystemrefs' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["File Extension of Encrypted Files"] = found_indicator.ioc_objects[0]['CustomFields']['fileextension'] if 'fileextension' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Virus Total"] = found_indicator.ioc_objects[0]['CustomFields']['url'] if 'url' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["MD5"] = found_indicator.ioc_objects[0]['CustomFields']['md5'] if 'md5' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["SHA1"] = found_indicator.ioc_objects[0]['CustomFields']['sha1'] if 'sha1' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"
                    profile_fields["SHA256"] = found_indicator.ioc_objects[0]['CustomFields']['sha256'] if 'sha256' in found_indicator.ioc_objects[0]['CustomFields'] else "n/a"

                elif found_indicator.ioc_objects[0]['indicator_type'] == "Threat Actor":
                    profile_fields["Threat Actor Classification"] = str(found_indicator.ioc_objects[0]['CustomFields']['threatactorclassification']).replace("'", "").replace("[", "").replace("]", "") if 'threatactorclassification' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Main Motivation"] = str(found_indicator.ioc_objects[0]['CustomFields']['mainmotivation']).replace("'", "").replace("[", "").replace("]", "") if 'mainmotivation' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Secondary Motivations"] = str(found_indicator.ioc_objects[0]['CustomFields']['secondarymotivations']).replace("'", "").replace("[", "").replace("]", "") if 'secondarymotivations' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Threat Actor Type"] = str(found_indicator.ioc_objects[0]['CustomFields']['threatactortypes']).replace("'", "").replace("[", "").replace("]", "") if 'threatactortypes' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Related Malware"] = str(found_indicator.ioc_objects[0]['CustomFields']['relatedmalware']).replace("'", "").replace("[", "").replace("]", "") if 'relatedmalware' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Associated Attack Vectors"] = str(found_indicator.ioc_objects[0]['CustomFields']['associatedattackvectors']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'associatedattackvectors' in found_indicator.ioc_objects[0]['CustomFields'] else "\n"

                elif found_indicator.ioc_objects[0]['indicator_type'] == "Tool":
                    profile_fields["Kill Chain Phases"] = str(found_indicator.ioc_objects[0]['CustomFields']['killchainphases']).replace("'", "").replace("[", "").replace("]", "") if 'killchainphases' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["Tool Type"] = str(found_indicator.ioc_objects[0]['CustomFields']['tooltypes']).replace("'", "").replace("[", "").replace("]", "") if 'tooltypes' in found_indicator.ioc_objects[0]['CustomFields'] else "\n"
                    profile_fields["Tool Version"] = str(found_indicator.ioc_objects[0]['CustomFields']['toolversion']) + "\n" if 'toolversion' in found_indicator.ioc_objects[0]['CustomFields'] else ""

                elif found_indicator.ioc_objects[0]['indicator_type'] == "Vulnerability":
                    profile_fields["Vulnerable Products"] = str(found_indicator.ioc_objects[0]['CustomFields']['vulnerableproducts']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'vulnerableproducts' in found_indicator.ioc_objects[0]['CustomFields'] else "\n"
                    profile_fields["CVE Description"] = found_indicator.ioc_objects[0]['CustomFields']['cvedescription'] if 'cvedescription' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["CVSS"] = found_indicator.ioc_objects[0]['CustomFields']['cvss'] if 'cvss' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["CVSS Score"] = str(found_indicator.ioc_objects[0]['CustomFields']['cvssscore']) + "\n" if 'cvssscore' in found_indicator.ioc_objects[0]['CustomFields'] else ""

                elif found_indicator.ioc_objects[0]['indicator_type'] == "Attack Pattern":
                    profile_fields["Kill Chain Phases"] = str(found_indicator.ioc_objects[0]['CustomFields']['killchainphases']).replace("'", "").replace("[", "").replace("]", "") if 'killchainphases' in found_indicator.ioc_objects[0]['CustomFields'] else ""
                    profile_fields["MITRE ATT&CK Techniques"] = "\n" + str(found_indicator.ioc_objects[0]['CustomFields']['mitreattacktechnique']).replace("'", "").replace("[", "").replace("]", "") + "\n" if 'mitreattacktechnique' in found_indicator.ioc_objects[0]['CustomFields'] else ""

                # add articles from TI Scraper at the end of the document
                article_list = ""
                if 'communitynotes' in found_indicator.ioc_objects[0]['CustomFields']:
                    for article in found_indicator.ioc_objects[0]['CustomFields']['communitynotes']:
                        article_list += article['notes'] + "\n\n"
                else:
                    article_list = "-"
                profile_fields["Media"] = article_list

                # check if the subdirectory for the documents exists and if not - create it
                if not os.path.exists("../10 Extracted Reports"):
                    os.makedirs("../10 Extracted Reports")

                # create document
                doc = OpenDocumentText()
                s = doc.styles
                # Heading
                title = Style(name="Title", family="paragraph")
                title.addElement(TextProperties(attributes={'fontsize':"14pt",'fontweight':"bold"}))
                headline=H(outlinelevel=0, stylename=title, text=indicator_profile + " Report")
                doc.text.addElement(headline)

                # create styles for the labels and values
                h3 = Style(name="Heading 3", family="paragraph")
                h3.addElement(TextProperties(attributes={'fontsize':"12pt", 'fontfamily':"Liberation Sans", 'fontweight':"bold"}))
                s.addElement(h3)

                paragraph = Style(name="Paragraph", family="paragraph")
                paragraph.addElement(TextProperties(attributes={'fontsize':"12pt", 'fontfamily':"Liberation Sans"}))
                s.addElement(paragraph)

                # add the fields from the profile to the document with key = label/description
                for key, value in profile_fields.items():
                    # if the value contains any line breaks
                    if "\n" in str(value):
                        elem = P(stylename=h3, text=key + ': ')
                        doc.text.addElement(elem)
                        for nl in value.split("\n"):
                            elem = P(stylename=paragraph, text=nl)
                            doc.text.addElement(elem)
                        elem = P(stylename=paragraph, text="")
                        doc.text.addElement(elem)
                    else:
                        elem = P(stylename=h3, text=key + ': ')
                        doc.text.addElement(elem)
                        elem = P(stylename=paragraph, text=str(value))
                        doc.text.addElement(elem)
                # save the document
                doc.save("../10 Extracted Reports/" + indicator_profile + " Report_" + datetime.now().strftime("%Y-%m-%d") + ".odt", addsuffix=False)
                print("Finished creation of the report for the requested indicator " + indicator_profile + "!")

        # catch exceptions
        except ApiException as e:
            print(e)
            print("Cannot extract the requested indicator profile. Cancelling...")

