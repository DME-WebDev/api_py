import requests
import json
import datetime
import time

pluginList=["Accelerated Mobile Pages",
            "Akismet Anti-Spam",
            "import and export users and customers",
            "reCaptcha by BestWebSoft",
            "Tutor LMS",
            "UpdraftPlus - Backup/Restore",
            "W3 Total Cache",
            "Web Stories",
            "Wordfence Login Security",
            "Wordfence Security",
            "WordPress Importer",
            "WP Crontrol",
            "WP Mail SMTP",
            "WPS Hide Login",
            "WPScan",
            "Yoast SEO",
            ]

def json_print(obj):
    text = json.dumps(obj, sort_keys=False, indent=1)
    print(text)

# Pub start/end dates need to be added to URL. Refer to API documentation if the video is unclear. 
# https://nvd.nist.gov/developers/vulnerabilities

def content_info(result):
    """
    This function will print out the result of the scan, results can be 0, 1 or greater than 0. ~~I did not put in scenario for greater than 1 result yet since I tried many inputs and have not seen any scan with greater than 2 vulnerabilities.~~
    Function will output the scan result.
    :param result: dict format of the site.
    :return: None
    """

    # Exception handling when key error occur. Either program need to be revise, or the input date is greater than 120 days.
    try:
        print("Scan Report")
        if result["totalResults"] == 0:
            print("\tNo Vulnerabilities found.")

        elif result["totalResults"] >= 1:
        # if result has exact one vulnerability
            resultCount = result["totalResults"]
            moreResults = 0
            if(resultCount > result["resultsPerPage"]):
                resultCount = result["resultsPerPage"]
                moreResults = result["totalResults"]-result["resultsPerPage"]
            for i in range(resultCount):
                scan_date = (f"{datetime.datetime.now():%Y-%m-%d}")
                published_date = result["result"]["CVE_Items"][i]["publishedDate"]
                description = result["result"]["CVE_Items"][i]["cve"]["description"]["description_data"][0]["value"]
                link = result["result"]["CVE_Items"][i]["cve"]["references"]["reference_data"][0]["url"]
                try:
                    confidentiality_impact = result["result"]["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                except:
                    confidentiality_impact = "Not Listed"
                try:
                    integrity_impact = result["result"]["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                except:
                    integrity_impact = "Not Listed"
                try:
                    availability_impact = result["result"]["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                except:
                    availability_impact = "Not Listed"
                try:
                    impact_level = result["result"]["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                except:
                    impact_level = "Not Listed"

                print("\tDate of Scan: {}.".format(scan_date),
                    "\n\tVulnerability Published Date: {}.".format(published_date),
                    "\n\tVulnerability Description: {}.".format(description),
                    "\n\tConfidentiality Impact: {}.".format(confidentiality_impact),
                    "\n\tIntegrity Impact: {}.".format(integrity_impact),
                    "\n\tAvailability Impact: {}.".format(availability_impact),
                    "\n\tImpact Level: {}.".format(impact_level),
                    "\n\tFor more information, Please see the Link below:",
                    "\n\t{}".format(link),
                    "\n"
                    )
            if(moreResults >= 1):
                print("\t+ {} more".format(moreResults))
            print("\n")
        else:
            print("\tMore than 1 vulnerability detected, please contact administrator.")

        return None

    except KeyError:
        print("\tPlease ensure date range is within 120 days or contact administrator.")


def makeURLs(pluginList):
    urls = []
    startDate = datetime.datetime.now() - datetime.timedelta(days=31)
    endDate = datetime.datetime.now()
    startDate = startDate.strftime("%Y-%m-%dT13:00:00:000 UTC-05:00")
    endDate = endDate.strftime("%Y-%m-%dT13:00:00:000 UTC-05:00")
    baseURL = "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=" + startDate + "&pubEndDate="+ endDate + "&keyword="
    for plugin in pluginList:
        pluginFixed = plugin.replace(" ", "+")
        urls.append(baseURL + pluginFixed)
    return urls


def main():
    urls = makeURLs(pluginList)
    #Get the Information from the website
    for i in range(len(urls)):
        print(pluginList[i], end=" ")
        response = requests.get(urls[i])
        #json_print(response.json())
        binary_content = response.content #output bin version of the information

        content = json.loads(binary_content) # Python dict format conversion
        content_info(content)

if __name__ == '__main__':
    main()
