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
