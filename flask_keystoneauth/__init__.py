# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import

import logging

from flask import session as flask_session
from keystoneclient import discover
from keystoneclient import exceptions as keystone_exceptions
from keystoneclient import session
from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient.auth.identity import v3 as v3_auth
from keystoneclient.exceptions import DiscoveryFailure
import pbr.version
import six
import six.moves.urllib.parse as urlparse


from flask_keystoneauth.i18n import _
from flask_keystoneauth.i18n import _LI

__version__ = pbr.version.VersionInfo(
    'flask_keystoneauth').version_string()

LOG = logging.getLogger(__name__)


class KeystoneAuth(object):
    def __init__(self, app=None,
                 fallback_endpoint=None, success_endpoint=None):
        self.app = app
        if app is not None:
            self.init_app(app)

        self.after_login_func = success_endpoint
        self.fallback_endpoint = fallback_endpoint
        self.auth_session = None
        self.auth_token = None

    def init_app(self, app):
        """This callback can be used to initialize an application for the
        use with this openid controller.

        .. versionadded:: 1.0
        """
        pass

    def signal_error(self, msg):
        """Signals an error.  It does this by storing the message in the
        session.  Use :meth:`errorhandler` to this method.
        """
        pass

    def fetch_error(self):
        """Fetches the error from the session.  This removes it from the
        session and returns that error.  This method is probably useless
        if :meth:`errorhandler` is used.
        """
        pass

    def authenticate(self, username=None, password=None):
        self.auth_session = self._get_keystone_session(username=username,
                                                       password=password)

        try:
            self.auth_token = self.auth_session.get_token()
            # TODO (e0ne): store auth_token in session
            flask_session['authorized'] = True
            flask_session.update()
            return True
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            LOG.info(_LI('Authentication failed: %s'), exc)
            return False
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            LOG.info(_LI('Error occurs during authorization: '), exc)
            return False

    def invalidate(self):
        if self.auth_session:
            self.auth_session.invalidate()
            flask_session.pop('authorized')

    def _get_keystone_session(self, **kwargs):
        # First create a Keystone session
        cacert = self.app.config['OS_CACERT']
        cert = self.app.config['OS_CERT']
        insecure = self.app.config['INSECURE'] = False

        if insecure:
            verify = False
        else:
            verify = cacert or True

        ks_session = session.Session(verify=verify, cert=cert)
        # Discover the supported keystone versions using the given url
        (v2_auth_url, v3_auth_url) = self._discover_auth_versions(
            session=ks_session,
            auth_url=self.app.config['OS_AUTH_URL'])

        username = kwargs.get('username') or self.app.config['OS_USERNAME']
        password = kwargs.get('password') or self.app.config['OS_PASSWORD']
        user_domain_name = self.app.config['OS_USER_DOMAIN_NAME']
        user_domain_id = self.app.config['OS_USER_DOMAIN_ID']

        auth = None
        if v3_auth_url and v2_auth_url:
            # Support both v2 and v3 auth. Use v3 if possible.
            if username:
                if user_domain_name or user_domain_id:
                    # Use v3 auth
                    auth = self.get_v3_auth(v3_auth_url,
                                            username=username,
                                            password=password)
                else:
                    # Use v2 auth
                    auth = self.get_v2_auth(v2_auth_url,
                                            username=username,
                                            password=password)

        elif v3_auth_url:
            # Support only v3
            auth = self.get_v3_auth(v3_auth_url,
                                    username=username,
                                    password=password)
        elif v2_auth_url:
            # Support only v2
            auth = self.get_v2_auth(v2_auth_url,
                                    username=username,
                                    password=password)
        else:
            raise Exception('Unable to determine the Keystone version '
                            'to authenticate with using the given '
                            'auth_url.')

        ks_session.auth = auth
        return ks_session

    def get_v2_auth(self, v2_auth_url, **kwargs):

        username = kwargs.get('username', self.app.config['OS_USERNAME'])
        password = kwargs.get('password', self.app.config['OS_PASSWORD'])
        tenant_id = self.app.config['OS_TENANT_ID']
        tenant_name = self.app.config['OS_TENANT_NAME']
        return v2_auth.Password(
            v2_auth_url,
            username=username,
            password=password,
            tenant_id=tenant_id,
            tenant_name=tenant_name)

    def get_v3_auth(self, v3_auth_url, **kwargs):

        username = kwargs.get('username', self.app.config['OS_USERNAME'])
        user_id = self.app.config['OS_USER_ID']
        user_domain_name = self.app.config['OS_USER_DOMAIN_NAME']
        user_domain_id = self.app.config['OS_USER_DOMAIN_ID']
        password = kwargs.get('password', self.app.config['OS_PASSWORD'])
        project_id = \
            self.app.config['OS_PROJECT_ID'] or self.app.config['OS_TENANT_ID']
        project_name = (self.app.config['OS_PROJECT_NAME']
                        or self.app.config['OS_TENANT_NAME'])
        project_domain_name = self.app.config['OS_PROJECT_DOMAIN_NAME']
        project_domain_id = self.app.config['OS_PROJECT_DOMAIN_ID']

        return v3_auth.Password(
            v3_auth_url,
            username=username,
            password=password,
            user_id=user_id,
            user_domain_name=user_domain_name,
            user_domain_id=user_domain_id,
            project_id=project_id,
            project_name=project_name,
            project_domain_name=project_domain_name,
            project_domain_id=project_domain_id,
        )

    def _discover_auth_versions(self, session, auth_url):
        # Discover the API versions the server is supporting based on the
        # given URL
        v2_auth_url = None
        v3_auth_url = None
        try:
            ks_discover = discover.Discover(session=session, auth_url=auth_url)
            v2_auth_url = ks_discover.url_for('2.0')
            v3_auth_url = ks_discover.url_for('3.0')
        except DiscoveryFailure:
            # Discovery response mismatch. Raise the error
            raise
        except Exception:
            # Some public clouds throw some other exception or doesn't support
            # discovery. In that case try to determine version from auth_url
            # API version from the original URL
            url_parts = urlparse.urlparse(auth_url)
            (scheme, netloc, path, params, query, fragment) = url_parts
            path = path.lower()
            if path.startswith('/v3'):
                v3_auth_url = auth_url
            elif path.startswith('/v2'):
                v2_auth_url = auth_url
            else:
                raise Exception('Unable to determine the Keystone'
                                ' version to authenticate with '
                                'using the given auth_url.')

        return (v2_auth_url, v3_auth_url)
