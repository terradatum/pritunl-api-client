#!/usr/bin/python

# Originally by Ijat.my
# https://github.com/ijat/pritunl-api-python

import base64
import hashlib
import hmac
import inspect
import json
import random
import uuid

import requests
import time
import urllib3
from requests import RequestException
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)


# Error exception handler
class PritunlError(Exception):
    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return 'PritunlError: {0}'.format(self.message)
        else:
            return 'PritunlError'


class Pritunl:
    r = None
    API_TOKEN = None
    BASE_URL = None
    API_SECRET = None

    def __init__(self, url, token, secret):
        self.BASE_URL = url
        self.API_TOKEN = token
        self.API_SECRET = secret

        # Sub classes
        self.server = self.ServerClass(self)
        self.organization = self.OrganizationClass(self)
        self.user = self.UserClass(self)
        self.key = self.KeyClass(self)

    class KeyClass:
        def __init__(self, parent=None):
            self.r = None
            self.parent = parent

        def get(self, org_id=None, user_id=None):
            try:
                if org_id and user_id:
                    self.r = self.parent.auth_request(method="GET", path="/key/{0}/{1}.tar".format(org_id, user_id))
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
                if self.r.status_code == 200:
                    return self.r
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

    class UserClass:

        def __init__(self, parent=None):
            self.r = None
            self.data_template = None
            self.headers = None
            self.parent = parent

        def get(self, org_id=None, user_id=None):
            try:
                if org_id and not user_id:
                    self.r = self.parent.auth_request(method="GET", path="/user/{0}".format(org_id))
                elif org_id and user_id:
                    self.r = self.parent.auth_request(method="GET", path="/user/{0}/{1}".format(org_id, user_id))
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def post(self, org_id=None, data=None):
            self.data_template = {
                'name': 'default_name',
                'email': None,
                'disabled': False,
            }
            self.data_template.update(data)
            try:
                self.headers = {'Content-Type': 'application/json'}
                self.r = self.parent.auth_request(method="POST", path="/user/{0}".format(org_id),
                                                  headers=self.headers,
                                                  data=json.dumps(self.data_template))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def put(self, org_id=None, user_id=None, data=None):
            try:
                self.headers = {'Content-Type': 'application/json'}
                self.r = self.parent.auth_request(method="PUT", path="/user/{0}/{1}".format(org_id, user_id),
                                                  headers=self.headers,
                                                  data=json.dumps(data))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def delete(self, org_id=None, user_id=None):
            try:
                self.r = self.parent.auth_request(method="DELETE", path="/user/{0}/{1}".format(org_id, user_id))
                if self.r.status_code == 200:
                    return True
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

    class OrganizationClass:

        def __init__(self, parent=None):
            self.r = None
            self.data_template = None
            self.headers = None
            self.parent = parent

        def get(self):
            try:
                self.r = self.parent.auth_request(method="GET", path="/organization")
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def post(self, data=None):
            self.headers = {'Content-Type': 'application/json'}
            self.data_template = {
                'name': 'default_organization',
                'auth_api': False
            }
            self.data_template.update(data)
            try:
                self.r = self.parent.auth_request(method="POST", path="/organization",
                                                  headers=self.headers,
                                                  data=json.dumps(self.data_template))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def put(self, org_id=None, data=None):
            self.headers = {'Content-Type': 'application/json'}
            self.data_template = {
                'name': 'default_organization',
                'auth_api': False
            }
            self.data_template.update(data)
            try:
                self.r = self.parent.auth_request(method="POST", path="/organization/{0}".format(org_id),
                                                  headers=self.headers,
                                                  data=json.dumps(self.data_template))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def delete(self, org_id=None):
            try:
                self.r = self.parent.auth_request(method="DELETE", path="/organization/{0}".format(org_id))
                if self.r.status_code == 200:
                    return True
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

    class ServerClass:

        def __init__(self, parent=None):
            self.header = {}
            self.data_template = {}
            self.r = None
            self.parent = parent

        def get(self, srv_id=None, org_id=None, out=None):
            try:
                if srv_id and not org_id and not out:
                    self.r = self.parent.auth_request(method="GET", path="/server/{0}".format(srv_id))
                elif srv_id and org_id and not out:
                    self.r = self.parent.auth_request(method="GET", path="/server/{0}/organization".format(srv_id))
                elif srv_id and out and not org_id:
                    self.r = self.parent.auth_request(method="GET", path="/server/{0}/output".format(srv_id))
                else:
                    self.r = self.parent.auth_request(method="GET", path="/server")
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def delete(self, srv_id=None, org_id=None, out=None):
            try:
                if srv_id and not out and not org_id:
                    self.r = self.parent.auth_request(method="DELETE", path="/server/{0}".format(srv_id))
                if srv_id and out and not org_id:
                    self.r = self.parent.auth_request(method="DELETE", path="/server/{0}/output".format(srv_id))
                if srv_id and org_id and not out:
                    self.r = self.parent.auth_request(method="DELETE",
                                                      path="/server/{0}/organization/{1}".format(srv_id, org_id))
                if self.r.status_code == 200:
                    return True
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except Exception:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def put(self, srv_id=None, operation=None, org_id=None, data=None):
            self.header = {'Content-Type': 'application/json'}
            try:
                if operation and not data and srv_id and not org_id:
                    self.r = self.parent.auth_request(method="PUT",
                                                      path="/server/{0}/operation/{1}".format(srv_id, operation))
                if srv_id and data and not operation and not org_id:
                    self.r = self.parent.auth_request(method="PUT",
                                                      path="/server/{0}".format(srv_id),
                                                      headers=self.header,
                                                      data=json.dumps(data)
                                                      )
                if srv_id and org_id and not data and not operation:
                    self.r = self.parent.auth_request(method="PUT",
                                                      path="/server/{0}/organization/{1}".format(srv_id, org_id)
                                                      )
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

        def post(self, data=None):
            self.data_template = {
                'name': 'default_server',
                'network': '10.{0}.{1}.0/24'.format(random.randrange(1, 254), random.randrange(1, 254)),
                'groups': [],
                'network_mode': 'tunnel',
                'network_start': None,
                'network_end': None,
                'restrict_routes': True,
                'ipv6': False,
                'ipv6_firewall': True,
                'bind_address': None,
                'port': random.randrange(1025, 20000),
                'protocol': 'tcp',
                'dh_param_bits': 1536,
                'multi_device': False,
                'dns_servers': ['8.8.8.8'],
                'search_domain': '',
                'otp_auth': False,
                'cipher': 'aes128',
                'hash': 'sha1',
                'jumbo_frames': False,
                'lzo_compression': False,
                'inter_client': True,
                'ping_interval': 10,
                'ping_timeout': 60,
                'link_ping_interval': 1,
                'link_ping_timeout': 5,
                'onc_hostname': None,
                'allowed_devices': None,
                'max_clients': 10,
                'replica_count': 1,
                'vxlan': True,
                'dns_mapping': False,
                'debug': False,
                'policy': None
            }
            self.data_template.update(data)
            try:
                self.header = {'Content-Type': 'application/json'}
                self.r = self.parent.auth_request(method="POST", path="/server",
                                                  headers=self.header,
                                                  data=json.dumps(self.data_template))
                if self.r.status_code == 200:
                    return json.dumps(self.r.json())
                else:
                    raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))
            except RequestException:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.parent.BASE_URL))

    def test(self):
        pass

    def ping(self) -> bool:
        try:
            self.r = self.auth_request(method="GET", path="/ping")
            if self.r.status_code == 200:
                return True
            else:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))
        except RequestException:
            raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))

    def check(self) -> bool:
        try:
            self.r = self.auth_request(method="GET", path="/check")
            if self.r.status_code == 200:
                return True
            else:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))
        except RequestException:
            raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))

    def setting(self):
        try:
            self.r = self.auth_request(method="GET", path="/settings")
            if self.r.status_code == 200:
                return json.dumps(self.r.json())
            else:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))
        except RequestException:
            raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))

    def status(self) -> str:
        try:
            self.r = self.auth_request(method="GET", path="/status")
            if self.r.status_code == 200:
                return json.dumps(self.r.json())
            else:
                raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))
        except RequestException:
            raise PritunlError("{0}:{1}".format(inspect.currentframe().f_code.co_name, self.BASE_URL))

    def last_response(self):
        return json.dumps(self.r.json())

    def auth_request(self, method, path, headers=None, data=None):
        auth_timestamp = str(int(time.time()))
        auth_nonce = uuid.uuid4().hex
        path_to_digest = [
            self.API_TOKEN,
            auth_timestamp,
            auth_nonce,
            method.upper(),
            path
        ]
        auth_string = '&'.join(path_to_digest + ([data] if data else []))

        hmac_digest = hmac.new(str.encode(self.API_SECRET), auth_string.encode('utf-8'), hashlib.sha256).digest()

        auth_signature = base64.b64encode(hmac_digest)
        auth_headers = {
            'Auth-Token': self.API_TOKEN,
            'Auth-Timestamp': auth_timestamp,
            'Auth-Nonce': auth_nonce,
            'Auth-Signature': auth_signature
        }

        if headers:
            auth_headers.update(headers)
        return getattr(requests, method.lower())(
            self.BASE_URL + path,
            verify=False,
            headers=auth_headers,
            data=data,
            timeout=30
        )
