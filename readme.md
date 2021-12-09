[comment]: # "Auto-generated SOAR connector documentation"
# BluVector

Publisher: BluVector  
Connector Version: 1\.0\.6  
Product Vendor: BluVector  
Product Name: BluVector  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 1\.1\.72  

This app allows executing actions like 'hunt file', 'detonate file', and 'event lookup'\.

BluVector App for Phantom Cyber
===============================

Use Cases:
Here are the current use cases that have been built into the app. There are more capabilities that are possible to add to this in the future.
1) Phantom can automatically poll BluVector for the latest events that are suspicious or greater and build a container that contains artifacts from the alert.
2) Phantom can query BluVector with a hash (MD5 or SHA256) to see if it has seen it and what the analysis was at the time.
3) Phantom can forward a file for analysis to BluVector to analyze and return the results.
4) Phantom can query BluVector with the BluVector Event ID and return the results.

## Pre-requisites
- Phantom Cyber instance with user that can install the app.
- BluVector credentials with API access and the API key.
    - The API key can be found on the BluVector GUI under the user profile settings and select "show API key".

## Phantom

### Installation
- In the Phantom GUI, under Administration -> Apps, press the **+APP** button.
- Select "Upload an app tarball or rpm for installation" and pick the bluvector.tgz from your file selector.
- If it has already been installed before, select "Replace an existing app".
- Press **INSTALL**.
- "BluVector" should now be in the app list on that page. 

### Configuration
- In the Phantom GUI, go to Administration -> Assets, and press the **+ASSET** button.
- Fill in the asset name and description.
- Select "Bluvector" for the product vendor and product name.
- Go to the "Asset Settings" tab, and fill in the IP/hostname and BluVector API key.
- If required, set the "Ingest Settings" and "Approval Settings" as needed. 


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a BluVector asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | string | BluVector API Key
**bv\_server** |  required  | string | BluVector IP/Hostname
**verify\_ssl\_cert** |  optional  | boolean | Verify Server SSL Certificate

### Supported Actions  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality\.  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\.  
[event lookup](#action-event-lookup) - Lookup a BluVector event using the Event ID\.  
[detonate file](#action-detonate-file) - Send file from the file vault to BluVector for analysis\.  
[hunt file](#action-hunt-file) - Query BluVector for hash\. \[md5, sha256\]  

## action: 'on poll'
Callback action for the on\_poll ingest functionality\.

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Container IDs to limit the ingestion to\. | string | 
**start\_time** |  optional  | Start of time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for\. | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for\. | numeric | 

#### Action Output
No Output  

## action: 'test connectivity'
Validate the asset configuration for connectivity\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'event lookup'
Lookup a BluVector event using the Event ID\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**bluvector\_event\_id** |  required  | BluVector Event ID of event to lookup\. | string |  `bluvector event id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.bluvector\_event\_id | string |  `bluvector event id` 
action\_result\.summary\.event\_status | string | 
action\_result\.summary\.app | string |  `network application` 
action\_result\.summary\.file\_status | string | 
action\_result\.summary\.flags | string | 
action\_result\.summary\.fname | string |  `file name` 
action\_result\.summary\.ftype | string | 
action\_result\.summary\.md5 | string |  `md5`  `hash` 
action\_result\.summary\.sha256 | string |  `sha256`  `hash` 
action\_result\.summary\.filesize | numeric | 
action\_result\.summary\.timestamp | string | 
action\_result\.summary\.yara\_file | string | 
action\_result\.summary\.yara\_rule | string | 
action\_result\.summary\.hector\_confidence | numeric | 
action\_result\.parameter\.hash | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate file'
Send file from the file vault to BluVector for analysis\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to send to BluVector for analysis\. | string |  `apk`  `doc`  `flash`  `jar`  `pdf`  `pe file`  `ppt`  `vault id`  `xls` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.bluvector\_event\_id | string |  `bluvector event id` 
action\_result\.summary\.event\_status | string | 
action\_result\.summary\.app | string |  `network application` 
action\_result\.summary\.file\_status | string | 
action\_result\.summary\.flags | string | 
action\_result\.summary\.fname | string |  `file name` 
action\_result\.summary\.ftype | string | 
action\_result\.summary\.md5 | string |  `md5`  `hash` 
action\_result\.summary\.sha256 | string |  `sha256`  `hash` 
action\_result\.summary\.filesize | numeric | 
action\_result\.summary\.timestamp | string | 
action\_result\.summary\.yara\_file | string | 
action\_result\.summary\.yara\_rule | string | 
action\_result\.summary\.hector\_confidence | numeric | 
action\_result\.parameter\.hash | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Query BluVector for hash\. \[md5, sha256\]

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | hash of the file to be queried | string |  `hash`  `sha256`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.bluvector\_event\_id | string |  `bluvector event id` 
action\_result\.summary\.event\_status | string | 
action\_result\.summary\.app | string |  `network application` 
action\_result\.summary\.src | string |  `ip` 
action\_result\.summary\.src\_port | string |  `port` 
action\_result\.summary\.dest | string |  `ip` 
action\_result\.summary\.dest\_port | string |  `port` 
action\_result\.summary\.host | string |  `host name` 
action\_result\.summary\.from | string |  `email` 
action\_result\.summary\.to | string |  `email` 
action\_result\.summary\.url | string |  `url` 
action\_result\.summary\.file\_status | string | 
action\_result\.summary\.flags | string | 
action\_result\.summary\.fname | string |  `file name` 
action\_result\.summary\.ftype | string | 
action\_result\.summary\.md5 | string |  `md5`  `hash` 
action\_result\.summary\.sha256 | string |  `sha256`  `hash` 
action\_result\.summary\.filesize | numeric | 
action\_result\.summary\.timestamp | string | 
action\_result\.summary\.yara\_file | string | 
action\_result\.summary\.yara\_rule | string | 
action\_result\.summary\.hector\_confidence | numeric | 
action\_result\.parameter\.hash | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 