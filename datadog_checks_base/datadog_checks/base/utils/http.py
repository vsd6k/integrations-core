# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import threading
import warnings
from contextlib import contextmanager

import requests
from six import iteritems, string_types
from six.moves.urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

from ..config import is_affirmative
try:
    import datadog_agent
except ImportError:
    from ..stubs import datadog_agent

STANDARD_FIELDS = {
    'password': None,
    'skip_proxy': False,
    'ssl_ca_cert': None,
    'ssl_cert': None,
    'ssl_ignore_warning': False,
    'ssl_private_key': None,
    'ssl_verify': True,
    'timeout': 10,
    'username': None,
}
DEFAULT_REMAPPED_FIELDS = {
    # TODO: Remove in 8.x
    'no_proxy': {'name': 'skip_proxy'},
}
PROXY_SETTINGS_DEFAULT = {
    'http': None,
    'https': None,
}
PROXY_SETTINGS_DISABLED = {
    # This will instruct `requests` to ignore the `HTTP_PROXY`/`HTTPS_PROXY`
    # environment variables. If the proxy options `http`/`https` are missing
    # or are `None` then `requests` will use the aforementioned environment
    # variables, hence the need to set each to an empty string.
    'http': '',
    'https': '',
}


class RequestsWrapper(object):
    warning_lock = threading.RLock()

    def __init__(self, instance, init_config, agent_config, remapper=None):
        default_fields = dict(STANDARD_FIELDS)

        # Update the default behavior for skipping proxies
        default_fields['skip_proxy'] = not is_affirmative(init_config.get('use_agent_proxy', True))

        # Populate with the default values
        config = {field: instance.get(field, value) for field, value in iteritems(default_fields)}

        # Support non-standard (legacy) configurations, for example:
        # {
        #     'disable_ssl_validation': {
        #         'name': 'ssl_verify',
        #         'default': False,
        #         'invert': True,
        #     },
        #     ...
        # }
        if remapper is None:
            remapper = {}

        remapper.update(DEFAULT_REMAPPED_FIELDS)

        for remapped_field, data in iteritems(remapper):
            field = data.get('name')

            # Ignore fields we don't recognize
            if field not in STANDARD_FIELDS:
                continue

            # Ignore remapped fields if the standard one is already used
            if field in instance:
                continue

            # Get value, with a possible default
            value = instance.get(remapped_field, data.get('default', default_fields[field]))

            # Invert booleans if need be
            if isinstance(value, bool) and data.get('invert'):
                value = not value

            config[field] = value

        # http://docs.python-requests.org/en/master/user/advanced/#timeouts
        timeout = int(config['timeout'])

        # http://docs.python-requests.org/en/master/user/authentication/
        auth = None
        if config['username'] and config['password']:
            auth = (config['username'], config['password'])

        # http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        verify = True
        if isinstance(config['ssl_ca_cert'], string_types):
            verify = config['ssl_ca_cert']
        elif not is_affirmative(config['ssl_verify']):
            verify = False

        # http://docs.python-requests.org/en/master/user/advanced/#client-side-certificates
        cert = None
        if isinstance(config['ssl_cert'], string_types):
            if isinstance(config['ssl_private_key'], string_types):
                cert = (config['ssl_cert'], config['ssl_private_key'])
            else:
                cert = config['ssl_cert']

        # http://docs.python-requests.org/en/master/user/advanced/#proxies
        # TODO: Remove support for Agent 5 config
        proxies = agent_config.get('proxy', datadog_agent.get_config('proxy'))
        no_proxy_uris = None

        if proxies:
            proxies = proxies.copy()

            # TODO: Pass `no_proxy` directly to requests once this issue is fixed:
            # https://github.com/kennethreitz/requests/issues/5000
            if 'no_proxy' in proxies:
                no_proxy_uris = proxies.pop('no_proxy')

                if isinstance(no_proxy_uris, string_types):
                    no_proxy_uris = no_proxy_uris.replace(';', ',').split(',')

        if not proxies:
            proxies = PROXY_SETTINGS_DEFAULT.copy()

        if is_affirmative(config['skip_proxy']):
            proxies = PROXY_SETTINGS_DISABLED.copy()

        # Default options
        self.options = {
            'auth': auth,
            'cert': cert,
            'proxies': proxies,
            'timeout': timeout,
            'verify': verify,
        }

        # For manual parsing until requests properly handles `no_proxy`
        self.no_proxy_uris = [] if no_proxy_uris is None else no_proxy_uris

        # Ignore warnings for lack of SSL validation
        self.ignore_ssl_warning = verify is False and config['ssl_ignore_warning']

        # For performance, if desired http://docs.python-requests.org/en/master/user/advanced/#session-objects
        self._session = None

    def get(self, url, persist=False, **options):
        return self._request('get', url, persist, options)

    def post(self, url, persist=False, **options):
        return self._request('post', url, persist, options)

    def head(self, url, persist=False, **options):
        return self._request('head', url, persist, options)

    def put(self, url, persist=False, **options):
        return self._request('put', url, persist, options)

    def patch(self, url, persist=False, **options):
        return self._request('patch', url, persist, options)

    def delete(self, url, persist=False, **options):
        return self._request('delete', url, persist, options)

    def _request(self, method, url, persist, options):
        if self.no_proxy_uris:
            parsed_uri = urlparse(url)

            for no_proxy_uri in self.no_proxy_uris:
                if no_proxy_uri in parsed_uri.netloc:
                    options.setdefault('proxies', PROXY_SETTINGS_DISABLED)
                    break

        with self.handle_ssl_warning():
            if persist:
                return getattr(self.session, method)(url, **options)
            else:
                return getattr(requests, method)(url, **self.populate_options(options))

    def populate_options(self, options):
        # Avoid needless dictionary update if there are no options
        if not options:
            return self.options

        for option, value in iteritems(self.options):
            # Make explicitly set options take precedence
            options.setdefault(option, value)

        return options

    @contextmanager
    def handle_ssl_warning(self):
        # Currently this doesn't actually do anything because a re-entrant
        # lock doesn't protect resources in the same thread, which is very
        # important as the Agent only uses one thread and disregards the GIL.
        with self.warning_lock:

            with warnings.catch_warnings():
                if self.ignore_ssl_warning:
                    warnings.simplefilter('ignore', InsecureRequestWarning)
                # Explicitly reset filter in case we're already ignoring in another
                # instance's lock. Remove this when we start using a real lock.
                else:
                    warnings.simplefilter('always', InsecureRequestWarning)

                yield

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()

            # Attributes can't be passed in the constructor
            for option, value in iteritems(self.options):
                setattr(self._session, option, value)

        return self._session

    def __del__(self):
        if self._session is not None:
            self._session.close()
