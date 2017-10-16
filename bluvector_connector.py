#!/usr/bin/env python
# Acuity Solutions Corporation ("Acuity") is willing to license its software and products, which contains proprietary
# or confidential information ("Software") or access to Software to the company or entity that will be using or
# accessing Software and documentation ("User") and that you represent as an employee or authorized agent ("you" or "your")
# only on the condition that you accept all of the terms of this license agreement.
#
# User acknowledges that Software and documentation within Acuity's Development Kit are copyrighted by and contain
# confidential information of Acuity. By accessing and/or using Software and documentation, you agree that while
# you may make derivative works of them, you:
#
# 1) shall not use Software and documentation or any derivative works for anything but your internal business purposes in
# conjunction with your licensed used of Acuity's software, nor
# 2)  provide or disclose the software and documentation or any derivative works to any third party.
#
# THIS SOFTWARE AND DOCUMENTATION IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ACUITY
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, DEATH, DISABILITY, OR BODILY HARM, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
# -----------------------------------------
# BluVector App Connector for Phantom
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
import simplejson as json
import requests
import re
import time
import os
import inspect
from datetime import timedelta, datetime
requests.packages.urllib3.disable_warnings()

_container_common = {
    'description': 'Container added by Phantom', 'run_automation': False}
_artifact_common = {
    'label': 'event',
    'type': 'network',
    'description': 'Artifact added by Phantom',
    'run_automation': False}
_severity_map = {0: 'low', 1: 'low', 2: 'medium', 3: 'high', 4: 'high'}
_status_map = {0: 'trusted', 1: 'info',
               2: 'suspicious', 3: 'malicious', 4: 'review'}


class BluVectorConnector(BaseConnector):

    def initialize(self):
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        self._ts_file_path = '%s/polling_data.json' % dirpath
        return phantom.APP_SUCCESS

    def _make_api_call(self, endpoint, payload=None):
        uri = 'https://%s/api/%s' % (self.server, endpoint)

        resp_json = None
        try:
            if payload:
                files = {'upload': payload}
                r = requests.post(uri, files=files,
                                  headers=self.headers, verify=self.verify)
            else:
                r = requests.get(uri, headers=self.headers,
                                 verify=self.verify)
        except Exception as e:
            self.bv_action_result.set_status(phantom.APP_ERROR, str(e))
            return (phantom.APP_ERROR, resp_json)

        try:
            resp_json = r.json()
        except Exception as e:
            return (
                self.bv_action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server not in json format: %s' %
                    r.text,
                    e),
                None)

        if r.status_code != requests.codes.ok:
            detail = resp_json.get('detail', 'Not specified')
            error_message = 'Error from server: %s\nDescription: %s' % (
                r.status_code, detail)
            return (
                self.bv_action_result.set_status(
                    phantom.APP_ERROR,
                    error_message),
                resp_json)

        return (
            self.bv_action_result.set_status(
                phantom.APP_SUCCESS),
            resp_json)

    def _get_hash_type(self, file_hash):
        """
        Get hash and return hash type.
        """
        hash_types = [{'regex': '^[0-9a-f]{32}$', 'hash_type': 'md5'},
                      # SHA1 not yet supported by BV. {'regex':
                      # '^[0-9a-f]{40}$', 'hash_type': 'sha1'},
                      {'regex': '^[0-9a-f]{64}$', 'hash_type': 'sha256'}]
        re_match = filter(lambda x: bool(
            re.match(x['regex'], file_hash)), hash_types)
        if re_match:
            return re_match[0]['hash_type']
        else:
            return None

    def _hunt_file(self, param):
        """
        Query all hash types (md5 or sha256 as of BV v2.0) on the BV with the hash provided in params.
            'curl -H "Authorization: Token <api_key>" https://<server>/api/events/query/?objects={"files.<hash_type>":"<file_hash>"}]}&limit=1'
        """
        file_hash = param['hash'].lower()
        # Use param['hash_type'] if it is provided, otherwise, use regex to get
        # it.
        hash_type = self._get_hash_type(file_hash)
        limit = param.get('limit', '1')
        query_dict = {'objects': '{"files.%s":"%s"}' % (
            hash_type, file_hash), 'limit': limit}
        query = '&'.join(['%s=%s' % (k, v) for (k, v) in query_dict.items()])

        endpoint = 'events/query/?%s' % query
        # self.bv_action_result.save_progress('Connecting to BluVector API.')
        returned, response = self._make_api_call(endpoint)
        if phantom.is_fail(returned):
            return self.bv_action_result.get_status()
        if not response.get('models'):
            self.bv_action_result.set_status(
                phantom.APP_SUCCESS, 'File not found in BluVector.')
            return self.bv_action_result.get_status()

        self.bv_action_result.add_data(response['models'][0])

        # Summary
        event_summary_keys = ['app', 'src', 'src_port',
                              'dest', 'dest_port', 'timestamp', 'host']
        http_summary_keys = ['uri', 'user-agent', 'server']
        smtp_summary_keys = ['from', 'to', 'subject']
        file_summary_keys = ['fname', 'ftype', 'md5', 'sha256', 'filesize']
        if 'models' in response:
            for models in response['models']:
                event_summary = {x: models['meta'].get(
                    x, '') for x in event_summary_keys}
                event_summary['event_status'] = _status_map[models.get(
                    'status', 1)]
                event_summary['bluvector_event_id'] = models.get('_id', '')
                if 'headers' in models['meta']:
                    if event_summary['app'] == 'http':
                        header_summary = {x: models['meta']['headers'].get(
                            x, '') for x in http_summary_keys}
                        if 'huri' in models['analysis']:
                            header_summary['url'] = models['analysis']['huri'].get(
                                'result', {}).get('normalizedurl', '')
                        else:
                            header_summary['url'] = event_summary['host'] + \
                                header_summary.get('uri', '')
                    elif event_summary['app'] == 'smtp':
                        header_summary = {x: models['meta']['headers'].get(
                            x, '') for x in smtp_summary_keys}
                    else:
                        header_summary = {}
                    event_summary.update(header_summary)
                for files in models['files']:
                    if files['md5'] == file_hash or files['sha256'] == file_hash:
                        file_summary = {x: files.get(x, '')
                                        for x in file_summary_keys}
                        file_summary['file_status'] = _status_map[files.get(
                            'status', 1)]
                        file_summary['flags'] = ', '.join(
                            files.get('flags', []))
                        if 'hector' in files['flags']:
                            file_summary['hector_confidence'] = files['analysis']['hector']['result']['confidence']
                        if 'clamav' in files['flags']:
                            file_summary['clamav_signature'] = files['analysis']['clamav']['result']['stream']
                        if 'yara' in files['flags']:
                            file_summary['yara_rule'] = files['analysis']['yara']['result'][0]['rule']
                            file_summary['yara_file'] = files['analysis']['yara']['result'][0]['namespace']
                        if 'intellookup' in files['flags']:
                            file_summary['intel_fields'] = files['intel']['flagged_fields']
                            file_summary['intel_providers'] = files['intel']['providers']
                            for provider in file_summary['intel_providers']:
                                file_summary['intel_%s_signature' %
                                             provider] = files['intel'][provider]['signatures'][0]
                        if 'pescanner' in files['analysis']:
                            file_summary['imphash'] = files['analysis']['pescanner']['result']['imphash']
                            file_summary['signed_PE'] = files['analysis']['pescanner']['result']['signed']
                            file_summary['PE_warnings'] = files['analysis']['pescanner']['result']['warnings']
                        if 'extractor' in files['analysis']:
                            fnames = []
                            for extracted in files['analysis']['extractor']['result']['files']:
                                fnames.append(extracted[0])
                            archived_files = ', '.join(fnames)
                            file_summary['archived_files'] = archived_files
                event_summary.update(file_summary)

        self.bv_action_result.update_summary(event_summary)
        self.bv_action_result.set_status(
            phantom.APP_SUCCESS, 'File found in BluVector.')
        return self.bv_action_result.get_status()

    def _analyze_file(self, param):
        """
        Use API to upload file to BV from Phantom vault for analysis.
        """
        self.save_progress('Sending file to BluVector for analysis.')

        endpoint = 'files/upload'
        vault_id = param['vault_id']
        try:
            payload = open(Vault.get_file_path(vault_id), 'rb')
        except BaseException:
            return self.bv_action_result.set_status(
                phantom.APP_ERROR,
                'File not found in vault (%s)' %
                vault_id)

        returned, response = self._make_api_call(endpoint, payload=payload)

        if phantom.is_fail(returned):
            return self.bv_action_result.get_status()

        try:
            event_id = response['event_id']
        except BaseException:
            return self.bv_action_result.set_status(
                phantom.APP_ERROR,
                'Missing event_id from response. (%s)' %
                response.get(
                    'error',
                    'Unknown error.'))

        self._lookup_and_parse(event_id)
        return self.bv_action_result.get_status()

    def _event_lookup(self, param):
        """
        Use API to lookup an event using the BluVector event id.
        """
        self.save_progress('Looking up BluVector Event ID.')

        event_id = param['bluvector_event_id']

        self._lookup_and_parse(event_id)
        return self.bv_action_result.get_status()

    def _lookup_and_parse(self, event_id):
        self.send_progress('Polling for analysis results...')
        start_time = datetime.utcnow()
        time_limit = start_time + timedelta(seconds=self.timeout)
        endpoint = 'events/%s' % event_id
        result_data = {}
        self.bv_action_result.add_data(result_data)
        count = 1
        while True:
            returned, response = self._make_api_call(endpoint)
            complete = returned and response is not None

            if not complete:
                if datetime.utcnow() > time_limit:
                    self.save_progress(
                        'Polling BluVector for Event ID #%s timed out after %s.' %
                        (event_id, self.timeout))
                    self.debug_print('Response: %s' % response)
                    self.bv_action_result.set_status(
                        phantom.APP_ERROR, 'Request timed out.')
                    break
                self.save_progress(
                    'Polling BluVector, attempt #%s' % count)
                count += 1
                time.sleep(10)
            if complete:
                result_data['result'] = response
                event_status = response.get('status', 'error')
                if event_status == 'error':
                    return self.bv_action_result.set_status(
                        phantom.APP_ERROR,
                        'Unexpected response for the event status, see raw output: %s' %
                        response)

                # Event status takes included files and built in rules
                if event_status == 'review':
                    msg = 'File needs furthur review.'
                elif event_status == 'malicious':
                    msg = 'File is malicious.'
                elif event_status == 'suspicious':
                    msg = 'File is suspicious.'
                elif event_status == 'info':
                    msg = 'File seems benign.'
                elif event_status == 'trusted':
                    msg = 'File is trusted.'
                else:
                    # Error
                    msg = 'Error parsing results. (event: %s)' % event_status

                event_summary_keys = ['app', 'timestamp']
                file_summary_keys = ['fname', 'ftype',
                                     'md5', 'sha256', 'filesize']
                if 'files' in response:
                    event_summary = {x: response['meta'].get(
                        x, '') for x in event_summary_keys}
                    event_summary['url'] = response.get('url', 'missing')
                    if "api/" in event_summary['url']:
                        event_summary['url'] = event_summary['url'].replace(
                            'api/', '')  # Remove 'api/' from url
                    event_summary['bluvector_event_id'] = response.get(
                        'id', 'missing')
                    event_summary['event_status'] = response.get(
                        'status', 'missing')
                    for files in response['files']:
                        file_summary = {x: files.get(x, '')
                                        for x in file_summary_keys}
                        file_summary['file_status'] = files.get(
                            'status', 'missing')
                        file_summary['flags'] = ', '.join(
                            files.get('flags', []))
                        if 'hector' in files['flags']:
                            file_summary['hector_confidence'] = files['analysis']['hector']['result']['confidence']
                        if 'clamav' in files['flags']:
                            file_summary['clamav_signature'] = files['analysis']['clamav']['result']['stream']
                        if 'yara' in files['flags']:
                            file_summary['yara_rule'] = files['analysis']['yara']['result'][0]['rule']
                            file_summary['yara_file'] = files['analysis']['yara']['result'][0]['namespace']
                        if 'intellookup' in files['flags']:
                            file_summary['intel_fields'] = files['intel']['flagged_fields']
                            file_summary['intel_providers'] = files['intel']['providers']
                            for provider in file_summary['intel_providers']:
                                file_summary['intel_%s_signature' %
                                             provider] = files['intel'][provider]['signatures'][0]
                        if 'pescanner' in files['analysis']:
                            file_summary['imphash'] = files['analysis']['pescanner']['result'].get(
                                'imphash', '')
                            file_summary['signed_PE'] = files['analysis']['pescanner']['result']['signed']
                            file_summary['PE_warnings'] = files['analysis']['pescanner']['result']['warnings']
                        if 'extractor' in files['analysis']:
                            fnames = []
                            for extracted in files['analysis']['extractor']['result']['files']:
                                fnames.append(extracted[0])
                            archived_files = ', '.join(fnames)
                            file_summary['archived_files'] = archived_files
                    event_summary.update(file_summary)

                print msg
                return self.bv_action_result.update_summary(event_summary)
                # return self.bv_action_result.update_summary({'message': msg,
                # 'url': 'https://%s/events/%s' % (self.server, event_id)})

    def _test_connectivity(self, param):
        """
        Used to test the connectivity from the Phantom UI. (Asset settings)
        Query the API to check if there is connectivity and if the API key is correct.
            'curl -H "Authorization: Token <api_key>" https://<server>/api/'
        """
        self.save_progress('Testing BluVector API Connectivity.')
        self.save_progress(
            phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self.server)

        try:
            # passed, response = self._make_api_call()
            r = requests.get('https://%s/api/' % self.server,
                             headers=self.headers, verify=self.verify)
        except Exception as e:
            msg = 'Error with api call: %s\nException: %s' % (
                self.server, e)
            # self.bv_action_result.set_status(phantom.APP_ERROR, msg)
            return self.set_status_save_progress(phantom.APP_ERROR, msg)

        if r.status_code != requests.codes.ok:
            if r.json:
                resp = r.json().get('detail', 'Not specified')
            else:
                resp = r.text
            msg = 'Connectivity failed to %s. Status code: %s\nresponse: %s' % (
                self.server, r.status_code, resp)
            self.bv_action_result.set_status(phantom.APP_ERROR)
            return self.set_status_save_progress(phantom.APP_ERROR, msg)
        self.bv_action_result.set_status(phantom.APP_SUCCESS)
        return self.set_status_save_progress(
            phantom.APP_SUCCESS, 'Test connectivity passed.')

    def _get_latest_ts(self):
        """
        Retrieve the last timestamp saved in tracking file. If not timestamp is present, return None.
        """
        try:
            with open(self._ts_file_path, 'r') as f:
                last_ts = json.loads(f.read()).get('ts', None)
        except BaseException:
            last_ts = None

        return last_ts

    def _save_latest_ts(self, ts):
        """
        Save the timestamp of the last event processed to a tracking file.
        """
        try:
            with open(self._ts_file_path, 'w') as f:
                f.write(json.dumps({'ts': ts}))
        except BaseException:
            pass

        return

    def _on_poll(self, param):
        """
        Used to poll BluVector to get alerts.
        Query the API for events set to Suspicious, Malicious, or Review.
            'curl -H "Authorization: Token <api_key>" https://<server>/api/events/query/?objects=
            {"status":{"$gte":2}}&limit=<max_events>
        """
        timestamp = None
        endpoint = 'events/query'
        # app_config = self.get_app_config()
        # Query max until last save is found
        query_dict = {}
        # Return everything with an event status of suspicious, malicious, or
        # review
        query_dict['objects'] = '{"$or":[{"status":2},{"status":3},{"status":4}]}'
        # Limit the number of events by the "container_count", if not provided,
        # return the last 10
        query_dict['limit'] = param.get('container_count', 10)
        # Get the timestamp of the last time on_poll was run and search everthing after that
        # If no timestamp exists, rely on the container count to limit the
        # events
        last_ts = self._get_latest_ts()
        if last_ts:
            query_dict['start'] = datetime.strptime(
                last_ts, '%Y-%m-%d %H:%M:%S.%f').strftime('%Y%m%dT%H%M%S')
        query = '&'.join(['%s=%s' % (k, v) for (k, v) in query_dict.items()])
        endpoint = 'events/query/?%s' % query
        # Return the response from BluVector
        status, response = self._make_api_call(endpoint)
        if phantom.is_fail(status):
            return self.get_status()

        count = response.get('count', 0)
        self.debug_print('Number of Retrieved Events: %d' % count)
        self.save_progress('Number of Retrieved Events: %d' % count)
        results = []
        container_id = 0
        # Parse response if there are more than 0 events returned.
        if count > 0:
            self.save_progress('Parsing events.')
            for event in response.get('models', {}):
                # Build Container
                ingest_event = {}
                results.append(ingest_event)
                container = {}
                ingest_event['container'] = container
                container.update(_container_common)
                # TODO: Is there a better way to name this?
                container['name'] = 'BluVector Alert'
                container_id += 1
                ingest_event['artifacts'] = artifacts = []
                # First artifact for event metadata
                artifact = {}
                cef = {}
                artifact['cef'] = cef
                artifacts.append(artifact)
                artifact.update(_artifact_common)
                artifact['source_data_identifier'] = event.get('_id', '')
                artifact['name'] = '%s BluVector Event Detected' % _status_map[event.get(
                    'status', '')].title()
                artifact['severity'] = _severity_map[event.get(
                    'status', 2)]
                # CEF output
                cef['applicationProtocol'] = event.get(
                    'meta', {}).get('app', '')
                cef['destinationAddress'] = event.get(
                    'meta', {}).get('dest', '')
                cef['destinationPort'] = event.get(
                    'meta', {}).get('dest_port', '')
                cef['sourceAddress'] = event.get('meta', {}).get('src', '')
                cef['sourcePort'] = event.get(
                    'meta', {}).get('src_port', '')
                cef['sourceHostName'] = event.get(
                    'meta', {}).get('host', '')
                cef['requestURL'] = event.get('meta', {}).get(
                    'headers', {}).get('uri', '')
                cef['requestClientApplication'] = event.get(
                    'meta', {}).get('headers', {}).get('user-agent', '')
                cef['requestCookies'] = event.get('meta', {}).get(
                    'headers', {}).get('cookie', '')
                cef['destinationUserName'] = event.get(
                    'meta', {}).get('headers', {}).get('to', '')
                cef['sourceUserName'] = event.get(
                    'meta', {}).get('headers', {}).get('from', '')

                timestamp = event.get('meta', {}).get('timestamp', None)
                if timestamp:
                    """
                    Change timestamp format
                        from: "2000-12-31 23:59:59:1234"  (%Y-%m-%d %H:%M:%S.%f)
                        to:   "Dec 31 2000 23:59:59"      (%b %d %Y %H:%M:%S)
                    """
                    cef_timestamp = datetime.strptime(
                        timestamp, '%Y-%m-%d %H:%M:%S.%f').strftime('%b %d %Y %H:%M:%S')
                    cef['startTime'] = cef_timestamp

                for each_file in event.get('files', []):
                    artifact = {}
                    cef = {}
                    artifact['cef'] = cef
                    artifact['data'] = each_file
                    artifacts.append(artifact)
                    artifact.update(_artifact_common)
                    artifact['source_data_identifier'] = each_file.get(
                        'sha256', 'None provided')
                    status = each_file['status']
                    artifact['name'] = '%sFile in Event' % (
                        _status_map[status].title() + ' ' if status >= 2 else '')
                    artifact['severity'] = _severity_map[status]
                    artifact['label'] = 'file'
                    cef['fileHash'] = each_file.get('md5', '')
                    cef['fileName'] = each_file.get('fname', '')
                    cef['fileType'] = each_file.get('ftype', '')

                    # Custom IDs
                    flags = []
                    detail = {}
                    for flag in each_file.get('flags', []):
                        flags.append(flag)
                        if flag == 'hector':
                            confidence = each_file.get(
                                'analysis',
                                {}).get(
                                flag,
                                {}).get(
                                'result',
                                {}).get(
                                'confidence',
                                None)
                            detail[flag] = '{0:.0f}%'.format(
                                confidence * 100)
                        elif flag == 'clamav':
                            detail[flag] = each_file.get('analysis', {}).get(
                                flag, {}).get('result', {}).get('stream', None)
                        elif flag == 'yara':
                            yara_results = each_file.get('analysis', {}).get(
                                flag, {}).get('result', [])
                            detail[flag] = ', '.join(
                                [x.get('rule', '') for x in yara_results])
                        elif flag == 'extractor':
                            detail[flag] = each_file.get('analysis', {}).get(
                                flag, {}).get('result', {}).get('msg', '')
                    if flags:
                        cef['deviceCustomString2Label'] = 'Malware Indicators'
                        cef['deviceCustomString2'] = '|'.join(flags)
                        cef['deviceCustomString3Label'] = 'Detailed Indicator Status'
                        cef['deviceCustomString3'] = ' '.join(
                            '%s: %s;' % (k, v) for k, v in detail.items())

        if timestamp:
            self._save_latest_ts(timestamp)

        if results:
            self.save_progress('Adding %s Container%s' %
                               (len(results), 's' if len(results) > 1 else ''))
            containers_processed = 0
            for result in results:
                if 'container' not in result:
                    print 'No container'
                    continue
                if len(result.get('artifacts', 0)) == 0:
                    print 'No artifacts'
                    continue
                containers_processed += 1
                self.save_progress('Adding container # %s' %
                                   containers_processed)
                ret_val, response, container_id = self.save_container(
                    result['container'])
                self.debug_print(
                    'save_container returns, value: %s, reason: %s, id: %s' %
                    (ret_val, response, container_id))
                if phantom.is_fail(ret_val):
                    print 'Save container failed'
                    continue
                if not container_id:
                    print 'No container_id'
                    continue
                artifacts_processed = 0
                for artifact in result['artifacts']:
                    artifact['container_id'] = container_id
                    artifacts_processed += 1
                    self.save_progress(
                        'Adding Container # %s, Artifact # %s' %
                        (containers_processed, artifacts_processed))
                    ret_val, response, artifact_id = self.save_artifact(
                        artifact)
                    self.debug_print(
                        'save_artifact returns, value: %s, reason: %s, id: %s' %
                        (ret_val, response, artifact_id))

            self.save_progress('Done')
        return self.set_status_save_progress(phantom.APP_SUCCESS)

    def handle_action(self, param):

        config = self.get_config()
        self.server = config.get('bv_server')
        api_key = config.get('api_key').lower()
        self.headers = {'Authorization': 'Token %s' % api_key}
        self.verify = config.get('verify_ssl_cert')
        self.timeout = 90

        result = None
        result = ActionResult(dict(param))
        self.add_action_result(result)
        self.bv_action_result = result

        action = self.get_action_identifier()
        if action == phantom.ACTION_ID_INGEST_ON_POLL:
            start_time = time.time()
            self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress('Poll time taken: %s' % human_time)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self._test_connectivity(param)
        elif action == 'hunt_file':
            self._hunt_file(param)
        elif action == 'detonate_file':
            self._analyze_file(param)
        elif action == 'event_lookup':
            self._event_lookup(param)
        else:
            raise ValueError('Action is not supported: %s' % action)

        return result.get_status()


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if len(sys.argv) < 2:
        print 'No test json specified.'
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)

        connector = BluVectorConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
