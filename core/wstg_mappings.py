"""OWASP Web Security Testing Guide traceability (generated; do not hand-edit).

WHAT WSTG IS, AND WHAT A MAPPING TO IT DOES NOT MEAN
-----------------------------------------------------
WSTG is a TESTING guide, not a vulnerability taxonomy. Its 97 entries are
procedures a tester performs against a RUNNING application: logging in as
another user, timing a response, clicking through a workflow, watching a
transport on the wire.

So mapping a finding to a test case does NOT mean this scanner performed that
test. It means the finding is the kind of weakness the test case is designed
to look for. A report that implied otherwise would claim WSTG conformance it
does not have, so the distinction is stated on every mapping and enforced in
the coverage block: `static_attestable` cases are the ones a source or asset
scan can speak to, and the rest are counted separately rather than folded in.

DIRECT is used only where the rule's detection target and the test case's
subject are the same weakness. Thematic siblings are RELATED: GENERIC_NOSQL_
INJECTION maps to the SQL-injection case as RELATED, and XXE maps to the
XML-injection case as RELATED, because WSTG v4.2 has no dedicated XXE case
and pretending otherwise would invent one.

PROVENANCE
----------
Extracted from the corpus checkout, not transcribed from memory:
    D:\\Data\\Code test\\prodtest\\web-security-testing-guide-master
    version v4.2
    97 test cases across 12 categories
    catalogue digest (SHA-256 over id|title|file):
      29E453B1EE9C2CE5256A78EC60E375A3982C9B8569B6034E262DF50F94033841

Ids were parsed from each section page's `|WSTG-XXX-NN|` table row. The
structured `_data/v42.yaml` carries a table of contents and no ids, so it is
not the source. Only identifiers and short titles are embedded; WSTG body
text is long-form prose under its own terms and is NOT vendored here.

LICENCE: UNVERIFIED, DELIBERATELY
-------------------------------
The checkout has no root LICENSE file. Unlike ASVS (CC BY-SA, G-092) and the
SANS guidelines (CC BY 4.0), no licence could be read, so none is asserted.
Identifiers and short titles are factual labels rather than expressive prose,
but the obligation is recorded as open rather than assumed away.
"""
from __future__ import annotations

WSTG_DOCUMENT = "OWASP Web Security Testing Guide"
WSTG_VERSION = "v4.2"
# T-15 (section 15, repo convention): relative to the checkout root --
# the machine-local absolute path stayed only in the PROVENANCE
# docstring above (prose, not an executable constant).
WSTG_SOURCE_PATH = "prodtest/web-security-testing-guide-master"
WSTG_CATALOGUE_SHA256 = "29E453B1EE9C2CE5256A78EC60E375A3982C9B8569B6034E262DF50F94033841"
WSTG_LICENSE = "UNVERIFIED - no LICENSE file at the checkout root; not asserted"
WSTG_DATASET_LABEL = f"{WSTG_DOCUMENT} {WSTG_VERSION}"
WSTG_STATUS = (
    "OWASP guidance. A TESTING guide, not a regulation, certification "
    "requirement, or vulnerability taxonomy. A mapping means the finding is "
    "the kind of weakness a test case looks for; it does NOT mean this scan "
    "performed that test."
)

DIRECT = "DIRECT"
RELATED = "RELATED"
UNMAPPED = "UNMAPPED"
WSTG_MAPPING_MODES = (DIRECT, RELATED, UNMAPPED)

WSTG_SEMANTICS = (
    "Evidence relevant to this WSTG test case. NOT a claim that the test was "
    "performed, NOT a statement that the application is untested against it, "
    "and NOT a WSTG conformance or certification claim."
)

WSTG_CATEGORY_TITLES = {"APIT": "API Testing", "ATHN": "Authentication Testing", "ATHZ": "Authorization Testing", "BUSL": "Business Logic Testing", "CLNT": "Client-side Testing", "CONF": "Configuration Management Testing", "CRYP": "Cryptography Testing", "ERRH": "Error Handling Testing", "IDNT": "Identity Management Testing", "INFO": "Information Gathering Testing", "INPV": "Input Validation Testing", "SESS": "Session Management Testing"}

# Category -> title.
WSTG_CATEGORIES = {
    "APIT": "API Testing",
    "ATHN": "Authentication Testing",
    "ATHZ": "Authorization Testing",
    "BUSL": "Business Logic Testing",
    "CLNT": "Client-side Testing",
    "CONF": "Configuration Management Testing",
    "CRYP": "Cryptography Testing",
    "ERRH": "Error Handling Testing",
    "IDNT": "Identity Management Testing",
    "INFO": "Information Gathering Testing",
    "INPV": "Input Validation Testing",
    "SESS": "Session Management Testing",
}

WSTG_TEST_CASES = {
    "WSTG-APIT-01": {
        "id": "WSTG-APIT-01",
        "category": "APIT",
        "category_title": "API Testing",
        "title": "Testing GraphQL",
        "source_page": "4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL.md",
        "static_attestable": False,
    },
    "WSTG-ATHN-01": {
        "id": "WSTG-ATHN-01",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Credentials Transported over an Encrypted Channel",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-02": {
        "id": "WSTG-ATHN-02",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Default Credentials",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-03": {
        "id": "WSTG-ATHN-03",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Weak Lock Out Mechanism",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-04": {
        "id": "WSTG-ATHN-04",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Bypassing Authentication Schema",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-05": {
        "id": "WSTG-ATHN-05",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Vulnerable Remember Password",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-06": {
        "id": "WSTG-ATHN-06",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Browser Cache Weaknesses",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-07": {
        "id": "WSTG-ATHN-07",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Weak Password Policy",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-08": {
        "id": "WSTG-ATHN-08",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Weak Security Question Answer",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-09": {
        "id": "WSTG-ATHN-09",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Weak Password Change or Reset Functionalities",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities.md",
        "static_attestable": True,
    },
    "WSTG-ATHN-10": {
        "id": "WSTG-ATHN-10",
        "category": "ATHN",
        "category_title": "Authentication Testing",
        "title": "Testing for Weaker Authentication in Alternative Channel",
        "source_page": "4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel.md",
        "static_attestable": True,
    },
    "WSTG-ATHZ-01": {
        "id": "WSTG-ATHZ-01",
        "category": "ATHZ",
        "category_title": "Authorization Testing",
        "title": "Testing Directory Traversal File Include",
        "source_page": "4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md",
        "static_attestable": True,
    },
    "WSTG-ATHZ-02": {
        "id": "WSTG-ATHZ-02",
        "category": "ATHZ",
        "category_title": "Authorization Testing",
        "title": "Testing for Bypassing Authorization Schema",
        "source_page": "4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.md",
        "static_attestable": True,
    },
    "WSTG-ATHZ-03": {
        "id": "WSTG-ATHZ-03",
        "category": "ATHZ",
        "category_title": "Authorization Testing",
        "title": "Testing for Privilege Escalation",
        "source_page": "4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation.md",
        "static_attestable": True,
    },
    "WSTG-ATHZ-04": {
        "id": "WSTG-ATHZ-04",
        "category": "ATHZ",
        "category_title": "Authorization Testing",
        "title": "Testing for Insecure Direct Object References",
        "source_page": "4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md",
        "static_attestable": True,
    },
    "WSTG-BUSL-01": {
        "id": "WSTG-BUSL-01",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Business Logic Data Validation",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-02": {
        "id": "WSTG-BUSL-02",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Ability to Forge Requests",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-03": {
        "id": "WSTG-BUSL-03",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Integrity Checks",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-04": {
        "id": "WSTG-BUSL-04",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test for Process Timing",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-05": {
        "id": "WSTG-BUSL-05",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Number of Times a Function Can Be Used Limits",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-06": {
        "id": "WSTG-BUSL-06",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Testing for the Circumvention of Work Flows",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-07": {
        "id": "WSTG-BUSL-07",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Defenses Against Application Misuse",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-08": {
        "id": "WSTG-BUSL-08",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Upload of Unexpected File Types",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types.md",
        "static_attestable": False,
    },
    "WSTG-BUSL-09": {
        "id": "WSTG-BUSL-09",
        "category": "BUSL",
        "category_title": "Business Logic Testing",
        "title": "Test Upload of Malicious Files",
        "source_page": "4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files.md",
        "static_attestable": False,
    },
    "WSTG-CLNT-01": {
        "id": "WSTG-CLNT-01",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for DOM-Based Cross Site Scripting",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-02": {
        "id": "WSTG-CLNT-02",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for JavaScript Execution",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-03": {
        "id": "WSTG-CLNT-03",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for HTML Injection",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-04": {
        "id": "WSTG-CLNT-04",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for Client-side URL Redirect",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-05": {
        "id": "WSTG-CLNT-05",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for CSS Injection",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-06": {
        "id": "WSTG-CLNT-06",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for Client-side Resource Manipulation",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-07": {
        "id": "WSTG-CLNT-07",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing Cross Origin Resource Sharing",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-08": {
        "id": "WSTG-CLNT-08",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for Cross Site Flashing",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-09": {
        "id": "WSTG-CLNT-09",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for Clickjacking",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-10": {
        "id": "WSTG-CLNT-10",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing WebSockets",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-11": {
        "id": "WSTG-CLNT-11",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing Web Messaging",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-12": {
        "id": "WSTG-CLNT-12",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing Browser Storage",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage.md",
        "static_attestable": True,
    },
    "WSTG-CLNT-13": {
        "id": "WSTG-CLNT-13",
        "category": "CLNT",
        "category_title": "Client-side Testing",
        "title": "Testing for Cross Site Script Inclusion",
        "source_page": "4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion.md",
        "static_attestable": True,
    },
    "WSTG-CONF-01": {
        "id": "WSTG-CONF-01",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test Network Infrastructure Configuration",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration.md",
        "static_attestable": True,
    },
    "WSTG-CONF-02": {
        "id": "WSTG-CONF-02",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test Application Platform Configuration",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration.md",
        "static_attestable": True,
    },
    "WSTG-CONF-03": {
        "id": "WSTG-CONF-03",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test File Extensions Handling for Sensitive Information",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information.md",
        "static_attestable": True,
    },
    "WSTG-CONF-04": {
        "id": "WSTG-CONF-04",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Review Old Backup and Unreferenced Files for Sensitive Information",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.md",
        "static_attestable": True,
    },
    "WSTG-CONF-05": {
        "id": "WSTG-CONF-05",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Enumerate Infrastructure and Application Admin Interfaces",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces.md",
        "static_attestable": True,
    },
    "WSTG-CONF-06": {
        "id": "WSTG-CONF-06",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test HTTP Methods",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md",
        "static_attestable": True,
    },
    "WSTG-CONF-07": {
        "id": "WSTG-CONF-07",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test HTTP Strict Transport Security",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.md",
        "static_attestable": True,
    },
    "WSTG-CONF-08": {
        "id": "WSTG-CONF-08",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test RIA Cross Domain Policy",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy.md",
        "static_attestable": True,
    },
    "WSTG-CONF-09": {
        "id": "WSTG-CONF-09",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test File Permission",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission.md",
        "static_attestable": True,
    },
    "WSTG-CONF-10": {
        "id": "WSTG-CONF-10",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test for Subdomain Takeover",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover.md",
        "static_attestable": True,
    },
    "WSTG-CONF-11": {
        "id": "WSTG-CONF-11",
        "category": "CONF",
        "category_title": "Configuration Management Testing",
        "title": "Test Cloud Storage",
        "source_page": "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage.md",
        "static_attestable": True,
    },
    "WSTG-CRYP-01": {
        "id": "WSTG-CRYP-01",
        "category": "CRYP",
        "category_title": "Cryptography Testing",
        "title": "Testing for Weak Transport Layer Security",
        "source_page": "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security.md",
        "static_attestable": True,
    },
    "WSTG-CRYP-02": {
        "id": "WSTG-CRYP-02",
        "category": "CRYP",
        "category_title": "Cryptography Testing",
        "title": "Testing for Padding Oracle",
        "source_page": "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle.md",
        "static_attestable": True,
    },
    "WSTG-CRYP-03": {
        "id": "WSTG-CRYP-03",
        "category": "CRYP",
        "category_title": "Cryptography Testing",
        "title": "Testing for Sensitive Information Sent via Unencrypted Channels",
        "source_page": "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels.md",
        "static_attestable": True,
    },
    "WSTG-CRYP-04": {
        "id": "WSTG-CRYP-04",
        "category": "CRYP",
        "category_title": "Cryptography Testing",
        "title": "Testing for Weak Encryption",
        "source_page": "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption.md",
        "static_attestable": True,
    },
    "WSTG-ERRH-01": {
        "id": "WSTG-ERRH-01",
        "category": "ERRH",
        "category_title": "Error Handling Testing",
        "title": "Testing for Improper Error Handling",
        "source_page": "4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md",
        "static_attestable": True,
    },
    "WSTG-ERRH-02": {
        "id": "WSTG-ERRH-02",
        "category": "ERRH",
        "category_title": "Error Handling Testing",
        "title": "Testing for Stack Traces",
        "source_page": "4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces.md",
        "static_attestable": True,
    },
    "WSTG-IDNT-01": {
        "id": "WSTG-IDNT-01",
        "category": "IDNT",
        "category_title": "Identity Management Testing",
        "title": "Test Role Definitions",
        "source_page": "4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions.md",
        "static_attestable": False,
    },
    "WSTG-IDNT-02": {
        "id": "WSTG-IDNT-02",
        "category": "IDNT",
        "category_title": "Identity Management Testing",
        "title": "Test User Registration Process",
        "source_page": "4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process.md",
        "static_attestable": False,
    },
    "WSTG-IDNT-03": {
        "id": "WSTG-IDNT-03",
        "category": "IDNT",
        "category_title": "Identity Management Testing",
        "title": "Test Account Provisioning Process",
        "source_page": "4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process.md",
        "static_attestable": False,
    },
    "WSTG-IDNT-04": {
        "id": "WSTG-IDNT-04",
        "category": "IDNT",
        "category_title": "Identity Management Testing",
        "title": "Testing for Account Enumeration and Guessable User Account",
        "source_page": "4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.md",
        "static_attestable": False,
    },
    "WSTG-IDNT-05": {
        "id": "WSTG-IDNT-05",
        "category": "IDNT",
        "category_title": "Identity Management Testing",
        "title": "Testing for Weak or Unenforced Username Policy",
        "source_page": "4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy.md",
        "static_attestable": False,
    },
    "WSTG-INFO-01": {
        "id": "WSTG-INFO-01",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage.md",
        "static_attestable": False,
    },
    "WSTG-INFO-02": {
        "id": "WSTG-INFO-02",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Fingerprint Web Server",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.md",
        "static_attestable": False,
    },
    "WSTG-INFO-03": {
        "id": "WSTG-INFO-03",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Review Webserver Metafiles for Information Leakage",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage.md",
        "static_attestable": False,
    },
    "WSTG-INFO-04": {
        "id": "WSTG-INFO-04",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Enumerate Applications on Webserver",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver.md",
        "static_attestable": False,
    },
    "WSTG-INFO-05": {
        "id": "WSTG-INFO-05",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Review Webpage Content for Information Leakage",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage.md",
        "static_attestable": False,
    },
    "WSTG-INFO-06": {
        "id": "WSTG-INFO-06",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Identify Application Entry Points",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points.md",
        "static_attestable": False,
    },
    "WSTG-INFO-07": {
        "id": "WSTG-INFO-07",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Map Execution Paths Through Application",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application.md",
        "static_attestable": False,
    },
    "WSTG-INFO-08": {
        "id": "WSTG-INFO-08",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Fingerprint Web Application Framework",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework.md",
        "static_attestable": False,
    },
    "WSTG-INFO-09": {
        "id": "WSTG-INFO-09",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Fingerprint Web Application",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application.md",
        "static_attestable": False,
    },
    "WSTG-INFO-10": {
        "id": "WSTG-INFO-10",
        "category": "INFO",
        "category_title": "Information Gathering Testing",
        "title": "Map Application Architecture",
        "source_page": "4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture.md",
        "static_attestable": False,
    },
    "WSTG-INPV-01": {
        "id": "WSTG-INPV-01",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Reflected Cross Site Scripting",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md",
        "static_attestable": True,
    },
    "WSTG-INPV-02": {
        "id": "WSTG-INPV-02",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Stored Cross Site Scripting",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md",
        "static_attestable": True,
    },
    "WSTG-INPV-03": {
        "id": "WSTG-INPV-03",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for HTTP Verb Tampering",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering.md",
        "static_attestable": True,
    },
    "WSTG-INPV-04": {
        "id": "WSTG-INPV-04",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for HTTP Parameter Pollution",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.md",
        "static_attestable": True,
    },
    "WSTG-INPV-05": {
        "id": "WSTG-INPV-05",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for SQL Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-06": {
        "id": "WSTG-INPV-06",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for LDAP Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-07": {
        "id": "WSTG-INPV-07",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for XML Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-08": {
        "id": "WSTG-INPV-08",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for SSI Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-09": {
        "id": "WSTG-INPV-09",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for XPath Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-10": {
        "id": "WSTG-INPV-10",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for IMAP SMTP Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-11": {
        "id": "WSTG-INPV-11",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Code Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-12": {
        "id": "WSTG-INPV-12",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Command Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-13": {
        "id": "WSTG-INPV-13",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Buffer Overflow",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Buffer_Overflow.md",
        "static_attestable": True,
    },
    "WSTG-INPV-14": {
        "id": "WSTG-INPV-14",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Incubated Vulnerability",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerability.md",
        "static_attestable": True,
    },
    "WSTG-INPV-15": {
        "id": "WSTG-INPV-15",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for HTTP Splitting Smuggling",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling.md",
        "static_attestable": True,
    },
    "WSTG-INPV-16": {
        "id": "WSTG-INPV-16",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for HTTP Incoming Requests",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests.md",
        "static_attestable": True,
    },
    "WSTG-INPV-17": {
        "id": "WSTG-INPV-17",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Host Header Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-18": {
        "id": "WSTG-INPV-18",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Server-side Template Injection",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection.md",
        "static_attestable": True,
    },
    "WSTG-INPV-19": {
        "id": "WSTG-INPV-19",
        "category": "INPV",
        "category_title": "Input Validation Testing",
        "title": "Testing for Server-Side Request Forgery",
        "source_page": "4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.md",
        "static_attestable": True,
    },
    "WSTG-SESS-01": {
        "id": "WSTG-SESS-01",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Session Management Schema",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema.md",
        "static_attestable": True,
    },
    "WSTG-SESS-02": {
        "id": "WSTG-SESS-02",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Cookies Attributes",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.md",
        "static_attestable": True,
    },
    "WSTG-SESS-03": {
        "id": "WSTG-SESS-03",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Session Fixation",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation.md",
        "static_attestable": True,
    },
    "WSTG-SESS-04": {
        "id": "WSTG-SESS-04",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Exposed Session Variables",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables.md",
        "static_attestable": True,
    },
    "WSTG-SESS-05": {
        "id": "WSTG-SESS-05",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Cross Site Request Forgery",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery.md",
        "static_attestable": True,
    },
    "WSTG-SESS-06": {
        "id": "WSTG-SESS-06",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Logout Functionality",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality.md",
        "static_attestable": True,
    },
    "WSTG-SESS-07": {
        "id": "WSTG-SESS-07",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing Session Timeout",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout.md",
        "static_attestable": True,
    },
    "WSTG-SESS-08": {
        "id": "WSTG-SESS-08",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Session Puzzling",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling.md",
        "static_attestable": True,
    },
    "WSTG-SESS-09": {
        "id": "WSTG-SESS-09",
        "category": "SESS",
        "category_title": "Session Management Testing",
        "title": "Testing for Session Hijacking",
        "source_page": "4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking.md",
        "static_attestable": True,
    },
}

WSTG_STATIC_ATTESTABLE_IDS = sorted(
    i for i, s in WSTG_TEST_CASES.items() if s["static_attestable"])

# Test cases a source scan cannot discharge, with the reason. Recorded so the
# coverage denominator is honest rather than flattering.
WSTG_NOT_STATIC_ATTESTABLE = {
    "WSTG-ATHN-01": "requires observing the transport channel at runtime",
    "WSTG-ATHN-03": "requires attempting repeated logins against a live system",
    "WSTG-ATHN-06": "requires browser cache inspection",
    "WSTG-ATHN-10": "requires a second channel to compare against",
    "WSTG-BUSL-04": "requires timing responses",
    "WSTG-BUSL-06": "requires walking the workflow as a user",
    "WSTG-BUSL-07": "requires demonstrating misuse",
    "WSTG-CLNT-08": "requires a Flash-capable browser",
    "WSTG-CLNT-10": "requires a live WebSocket endpoint",
    "WSTG-CLNT-11": "requires a live message channel",
    "WSTG-CLNT-12": "requires browser storage inspection",
    "WSTG-CONF-01": "network infrastructure, not application source",
    "WSTG-CONF-10": "subdomain takeover requires DNS resolution and a provider check",
    "WSTG-CONF-11": "cloud storage requires provider credentials",
    "WSTG-CRYP-02": "requires an oracle measurement at runtime",
    "WSTG-IDNT-02": "requires registering accounts",
    "WSTG-IDNT-03": "requires an account provisioning system",
    "WSTG-IDNT-04": "requires enumerating accounts at runtime",
    "WSTG-INFO-01": "requires search engine queries",
    "WSTG-INFO-02": "requires probing a live server",
    "WSTG-INFO-04": "requires enumerating a live host",
    "WSTG-INFO-06": "entry-point mapping needs the running application",
    "WSTG-INFO-07": "execution-path mapping needs the running application",
    "WSTG-INFO-09": "requires probing a live application",
    "WSTG-INFO-10": "architecture mapping is an interview and review activity",
    "WSTG-SESS-06": "requires exercising logout",
    "WSTG-SESS-07": "requires waiting out the timeout",
    "WSTG-SESS-08": "requires a burst of crafted requests",
    "WSTG-SESS-09": "requires hijacking a live session",
}

# rule_id -> (test case, mode, rationale)
WSTG_BY_RULE_ID = {
    "AUTH_BYPASS": {
        "case": "WSTG-ATHN-04",
        "mode": "DIRECT",
        "rationale": "Authentication bypass.",
    },
    "CLICKJACKING_MISSING_FRAME_OPTIONS": {
        "case": "WSTG-CLNT-09",
        "mode": "DIRECT",
        "rationale": "Framing not restricted, which is what WSTG-CLNT-09 tests for.",
    },
    "CSRF_PROTECTION_MISSING": {
        "case": "WSTG-SESS-05",
        "mode": "DIRECT",
        "rationale": "Missing cross-site request forgery protection.",
    },
    "DOM_XSS": {
        "case": "WSTG-CLNT-01",
        "mode": "DIRECT",
        "rationale": "DOM-based cross-site scripting.",
    },
    "GENERIC_NOSQL_INJECTION": {
        "case": "WSTG-INPV-05",
        "mode": "RELATED",
        "rationale": "NoSQL injection is a sibling of the injection class WSTG-INPV-05 covers but is a different weakness; the link is thematic, so RELATED not DIRECT.",
    },
    "HARDCODED_CREDENTIAL": {
        "case": "WSTG-ATHN-02",
        "mode": "RELATED",
        "rationale": "Hardcoded credentials are the default/guessable credential class WSTG-ATHN-02 covers; RELATED because the rule finds a credential in source rather than a default account at runtime.",
    },
    "HOST_HEADER_INJECTION": {
        "case": "WSTG-INPV-17",
        "mode": "DIRECT",
        "rationale": "Host header injection.",
    },
    "HTTP_RESPONSE_SPLITTING": {
        "case": "WSTG-INPV-15",
        "mode": "DIRECT",
        "rationale": "HTTP response splitting/smuggling.",
    },
    "IDOR": {
        "case": "WSTG-ATHZ-04",
        "mode": "DIRECT",
        "rationale": "A reference to a record without an ownership check.",
    },
    "JAVA_J3_COMMAND_INJECTION": {
        "case": "WSTG-INPV-12",
        "mode": "DIRECT",
        "rationale": "Command injection, older Java level.",
    },
    "JAVA_J3_LDAP": {
        "case": "WSTG-INPV-06",
        "mode": "DIRECT",
        "rationale": "LDAP injection, older level.",
    },
    "JAVA_J3_SQL_INJECTION": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "Same weakness, older Java source level.",
    },
    "JAVA_J3_TRUST_BOUNDARY_VIOLATION": {
        "case": "WSTG-ATHZ-02",
        "mode": "RELATED",
        "rationale": "Trust-boundary crossing is closest to bypassing the authorization schema; RELATED because the two are not identical.",
    },
    "JAVA_J4_XSS": {
        "case": "WSTG-INPV-01",
        "mode": "DIRECT",
        "rationale": "Reflected XSS, older source level.",
    },
    "JAVA_J5_CMD": {
        "case": "WSTG-INPV-12",
        "mode": "DIRECT",
        "rationale": "Process execution with tainted input.",
    },
    "JAVA_J5_LDAP": {
        "case": "WSTG-INPV-06",
        "mode": "DIRECT",
        "rationale": "LDAP search filter injection.",
    },
    "JAVA_J5_PATH": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "Filesystem access with request-controlled path.",
    },
    "JAVA_J5_SQL": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "JDBC query execution with request-controlled input is the SQL injection weakness WSTG-INPV-05 tests for.",
    },
    "JAVA_J5_XPATH": {
        "case": "WSTG-INPV-09",
        "mode": "DIRECT",
        "rationale": "XPath expression injection.",
    },
    "JAVA_J5_XSS": {
        "case": "WSTG-INPV-01",
        "mode": "DIRECT",
        "rationale": "Request data reaching the response unencoded is reflected XSS.",
    },
    "JAVA_JDBC_SQL_CONCAT": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "String concatenation into a JDBC statement.",
    },
    "JAVA_PATH_TRAVERSAL_FILE": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "File path traversal.",
    },
    "JAVA_TAINT_COMMAND_INJECTION": {
        "case": "WSTG-INPV-12",
        "mode": "DIRECT",
        "rationale": "Taint flow into a process exec.",
    },
    "JAVA_TAINT_LDAP_INJECTION": {
        "case": "WSTG-INPV-06",
        "mode": "DIRECT",
        "rationale": "Taint flow into an LDAP filter.",
    },
    "JAVA_TAINT_PATH_TRAVERSAL": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "Taint flow into a filesystem path.",
    },
    "JAVA_TAINT_SQL_INJECTION": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "AST-confirmed flow to a SQL sink.",
    },
    "JAVA_TAINT_XPATH_INJECTION": {
        "case": "WSTG-INPV-09",
        "mode": "DIRECT",
        "rationale": "Taint flow into XPath evaluation.",
    },
    "JAVA_WEAK_CIPHER": {
        "case": "WSTG-CRYP-04",
        "mode": "DIRECT",
        "rationale": "Weak cipher selected.",
    },
    "JAVA_WEB_COOKIE_MISSING_SECURITY_FLAGS": {
        "case": "WSTG-SESS-02",
        "mode": "DIRECT",
        "rationale": "The rule reports a cookie without Secure, which is a cookie-attribute check: exactly WSTG-SESS-02's subject.",
    },
    "JAVA_XXE_PARSER": {
        "case": "WSTG-INPV-07",
        "mode": "RELATED",
        "rationale": "WSTG v4.2 has no dedicated XXE test case. INPV-07 (XML Injection) is the nearest XML-family procedure, so the link is reported as RELATED rather than pretending an XXE case exists.",
    },
    "MISSING_HSTS": {
        "case": "WSTG-CONF-07",
        "mode": "DIRECT",
        "rationale": "HTTP Strict Transport Security not asserted in configuration.",
    },
    "NODE_FS_TRAVERSAL": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "Node filesystem traversal.",
    },
    "NODE_SSRF_DYNAMIC_URL": {
        "case": "WSTG-INPV-19",
        "mode": "DIRECT",
        "rationale": "Server-side fetch of a dynamic URL.",
    },
    "OPEN_REDIRECT": {
        "case": "WSTG-CLNT-04",
        "mode": "RELATED",
        "rationale": "Redirect to an attacker-influenced URL; RELATED because WSTG-CLNT-04 is written for client-side redirects.",
    },
    "PHP_COMMAND_INJECTION": {
        "case": "WSTG-INPV-12",
        "mode": "DIRECT",
        "rationale": "PHP command injection.",
    },
    "PHP_RAW_ECHO_XSS": {
        "case": "WSTG-INPV-01",
        "mode": "DIRECT",
        "rationale": "Raw echo of request data is reflected XSS.",
    },
    "PHP_SQL_CONCAT": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "PHP query built by concatenation.",
    },
    "SESSION_FIXATION": {
        "case": "WSTG-SESS-03",
        "mode": "DIRECT",
        "rationale": "Session identifier not rotated.",
    },
    "SPRING_MULTIPART_TRAVERSAL": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "Spring multipart filename traversal.",
    },
    "SSTI": {
        "case": "WSTG-INPV-18",
        "mode": "DIRECT",
        "rationale": "Server-side template injection.",
    },
    "STACK_TRACE_DISCLOSURE": {
        "case": "WSTG-ERRH-02",
        "mode": "DIRECT",
        "rationale": "Stack trace returned to the caller.",
    },
    "TAINT_MULTIPART_TRAVERSAL": {
        "case": "WSTG-ATHZ-01",
        "mode": "DIRECT",
        "rationale": "Multipart filename reaching a filesystem call.",
    },
    "TAINT_PHP_COMMAND_INJECTION": {
        "case": "WSTG-INPV-12",
        "mode": "DIRECT",
        "rationale": "Taint flow into a PHP shell call.",
    },
    "TAINT_PHP_SQL_INJECTION": {
        "case": "WSTG-INPV-05",
        "mode": "DIRECT",
        "rationale": "Taint flow into a PHP SQL call.",
    },
    "TAINT_SSRF_EXPANDED": {
        "case": "WSTG-INPV-19",
        "mode": "DIRECT",
        "rationale": "Server-side request to an attacker-influenced URL.",
    },
    "VERBOSE_ERROR_MESSAGE": {
        "case": "WSTG-ERRH-01",
        "mode": "DIRECT",
        "rationale": "Improper error handling.",
    },
    "WEAK_HASH_MD5": {
        "case": "WSTG-CRYP-04",
        "mode": "DIRECT",
        "rationale": "MD5 chosen for a security purpose.",
    },
    "WEAK_HASH_SHA1": {
        "case": "WSTG-CRYP-04",
        "mode": "DIRECT",
        "rationale": "SHA-1 chosen for a security purpose.",
    },
    "WEAK_PASSWORD_POLICY": {
        "case": "WSTG-ATHN-07",
        "mode": "DIRECT",
        "rationale": "Weak password policy.",
    },
    "WEAK_RANDOM": {
        "case": "WSTG-CRYP-04",
        "mode": "RELATED",
        "rationale": "Weak randomness underlies a weak-primitive weakness; RELATED because WSTG-CRYP-04 is about encryption.",
    },
    "XSS_OUTPUT_ENCODING": {
        "case": "WSTG-INPV-01",
        "mode": "RELATED",
        "rationale": "Missing output encoding is the mitigation whose absence INPV-01 looks for; RELATED because the rule names the control, not the payload.",
    },
}

WSTG_UNMAPPED_RATIONALE = (
    "No WSTG test case was attributed. WSTG is organised as procedures against "
    "a running application, and most of its 97 cases are interactive, "
    "deployment-dependent or runtime-observable; the inject'able subset is "
    "the injection, authorization, session, cryptography, error-handling, "
    "client-side and configuration families. A finding outside those families "
    "usually has no WSTG home, and that is a statement about WSTG's scope "
    "rather than about this finding."
)

WSTG_LICENCE_GAP = (
    "The WSTG checkout carries no root LICENSE file, so no licence is asserted "
    "for the identifiers and titles embedded here. Treat redistribution as an "
    "open question until the terms are read from an authoritative source."
)


def wstg_label(cid: str) -> str:
    spec = WSTG_TEST_CASES.get(str(cid or "").strip()) or {}
    return " - ".join(x for x in (spec.get("id", cid), spec.get("title")) if x)


def wstg_reference(rule_id: str = "", vuln_type: str = "") -> dict:
    """Pinned WSTG attribution. Fails closed to UNMAPPED."""
    rid = str(rule_id or "").strip().upper()
    entry = WSTG_BY_RULE_ID.get(rid)
    base = {
        "wstg_case": "",
        "wstg_label": "",
        "wstg_title": "",
        "wstg_category": "",
        "wstg_category_title": "",
        "wstg_static_attestable": None,
        "wstg_mapping_mode": UNMAPPED,
        "wstg_rationale": "",
        "wstg_dataset": WSTG_DATASET_LABEL,
        "wstg_version": WSTG_VERSION,
        "wstg_license": WSTG_LICENSE,
        "wstg_status": WSTG_STATUS,
        "wstg_semantics": WSTG_SEMANTICS,
    }
    if entry is None:
        base["wstg_rationale"] = WSTG_UNMAPPED_RATIONALE
        return base
    spec = WSTG_TEST_CASES.get(entry["case"]) or {}
    base["wstg_case"] = entry["case"]
    base["wstg_label"] = wstg_label(entry["case"])
    base["wstg_title"] = spec.get("title", "")
    base["wstg_category"] = spec.get("category", "")
    base["wstg_category_title"] = spec.get("category_title", "")
    base["wstg_static_attestable"] = spec.get("static_attestable")
    base["wstg_mapping_mode"] = entry["mode"]
    base["wstg_rationale"] = entry["rationale"]
    if entry["mode"] == RELATED and entry["case"] in WSTG_NOT_STATIC_ATTESTABLE:
        base["wstg_rationale"] += (" This test case is not statically "
            "attestable: " + WSTG_NOT_STATIC_ATTESTABLE[entry["case"]] + ".")
    return base


def enrich_with_wstg(finding: dict) -> dict:
    finding.update(wstg_reference(finding.get("rule_id", "")))
    return finding


def wstg_coverage(rule_ids=()) -> dict:
    """Reachability summary with every denominator stated."""
    from collections import Counter

    def tally(keys):
        counts = Counter()
        mapped, unmapped, static_hits = [], [], []
        for k in keys:
            ref = wstg_reference(k)
            counts[ref["wstg_mapping_mode"]] += 1
            if ref["wstg_mapping_mode"] == UNMAPPED:
                unmapped.append(k)
            else:
                mapped.append(k)
                if ref["wstg_static_attestable"]:
                    static_hits.append(ref["wstg_case"])
        return {
            "total": len(keys),
            "by_mode": dict(counts),
            "mapped": sorted(mapped),
            "unmapped": sorted(unmapped),
            "coverage_ratio": (len(mapped) / len(keys)) if keys else 0.0,
            "cases_reached": sorted(set(
                wstg_reference(k)["wstg_case"] for k in mapped)),
            "cases_statically_attestable": sorted(set(static_hits)),
        }

    fam = tally(list(rule_ids))
    fam["catalogue_size"] = len(WSTG_TEST_CASES)
    fam["catalogue_categories"] = len(WSTG_CATEGORIES)
    fam["catalogue_static_attestable"] = len(WSTG_STATIC_ATTESTABLE_IDS)
    fam["catalogue_not_static_attestable"] = (
        len(WSTG_TEST_CASES) - len(WSTG_STATIC_ATTESTABLE_IDS))
    fam["rules_mapped"] = len(WSTG_BY_RULE_ID)
    fam["dataset"] = WSTG_DATASET_LABEL
    fam["status"] = WSTG_STATUS
    fam["semantics"] = (
        "Ratios describe reachability into WSTG guidance. They are NOT "
        "conformance and NOT a certification score. A WSTG test case is a "
        "procedure against a running application; mapping a finding to one "
        "does not mean the procedure was performed. Cases a source scan cannot "
        "discharge are reported separately rather than counted as covered."
    )
    fam["licence_gap"] = WSTG_LICENCE_GAP
    return fam
