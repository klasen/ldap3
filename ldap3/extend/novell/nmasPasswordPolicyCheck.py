"""
"""

# Author: Norbert Klasen
#
# Copyright Open Text
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from ..operation import ExtendedOperation
from ...protocol.novell import NmasPasswordPolicyCheckRequestValue, NmasPasswordPolicyCheckResponseValue, NMAS_LDAP_EXT_VERSION
from ...utils.dn import safe_dn


class NmasPasswordPolicyCheck(ExtendedOperation):
    def config(self):
        self.request_name = '2.16.840.1.113719.1.39.42.100.17'
        self.response_name = '2.16.840.1.113719.1.39.42.100.18'
        self.request_value = NmasPasswordPolicyCheckRequestValue()
        self.asn1_spec = NmasPasswordPolicyCheckResponseValue()
        self.response_attribute = 'error'

    def __init__(self, connection, user, password, controls=None):
        """Checks the specified password to determine if it matches the password policy that is effective for the specified user. If a null password is passed in, the transport will set a flag to check the existing password."""
        ExtendedOperation.__init__(self, connection, controls)  # calls super __init__()

        if connection.check_names:
            user = safe_dn(user)

        self.request_value['nmasver'] = NMAS_LDAP_EXT_VERSION
        self.request_value['reqdn'] = user
        if password == None:
            self.request_value['flags']['checkCurrent'] = 1
        else: 
            self.request_value['flags']['checkCurrent'] = 0
            self.request_value['flags']['checkPassword']['password'] = password

    def populate_result(self):
        if self.decoded_response:
            self.result['nmasver'] = int(self.decoded_response['nmasver'])
            self.result['error'] = int(self.decoded_response['err'])
            try:
                self.result['data'] = str(self.decoded_response['data']) if self.decoded_response['data'].hasValue() else None
            except TypeError:
                self.result['data'] = None
