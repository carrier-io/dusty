#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011,E0401

#   Copyright 2023 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
    SSL tools
"""

import os
import atexit
import tempfile


custom_ca_bundle = None  # pylint: disable=C0103
set_env_vars = []  # pylint: disable=C0103


def init(ssl_certs_env_str):  # pylint: disable=R0912,R0914
    """ Create custom CA bundle """
    global custom_ca_bundle  # pylint: disable=W0603,C0103
    global set_env_vars  # pylint: disable=W0603,C0103
    #
    # Configured locations/certs
    #
    certs = [item.strip() for item in ssl_certs_env_str.split(",") if item.strip()]
    cert_data = []
    #
    # Load OS store and 'certifi' (if installed)
    #
    try:
        import ssl  # pylint: disable=C0415
        os_verify_paths = ssl.get_default_verify_paths()
        #
        for item in [
                os_verify_paths.cafile, os_verify_paths.capath,
                os_verify_paths.openssl_cafile, os_verify_paths.openssl_capath,
        ]:
            if item not in certs:
                certs.append(item)
    except:  # pylint: disable=W0702
        pass
    #
    try:
        import certifi  # pylint: disable=C0415
        certs.append(certifi.contents())
    except:  # pylint: disable=W0702
        pass
    #
    # Get all certs, cert files and cert paths
    #
    for item in certs:  # pylint: disable=R1702
        if os.path.isdir(item):
            try:
                for root, _, files in os.walk(item):
                    for name in files:
                        try:
                            with open(os.path.join(root, name), "r") as file:
                                cert_data.append(file.read())
                        except:  # pylint: disable=W0702
                            pass
            except:  # pylint: disable=W0702
                pass
        elif os.path.isfile(item):
            try:
                with open(item, "r") as file:
                    cert_data.append(file.read())
            except:  # pylint: disable=W0702
                pass
        else:
            cert_data.append(str(item).replace("|", "\n"))
    #
    # Save to custom CA bundle
    #
    output_file_fd, output_file = tempfile.mkstemp()
    os.close(output_file_fd)
    #
    with open(output_file, "w") as file:
        file.write("\n".join(cert_data))
    #
    custom_ca_bundle = output_file
    #
    # Set env vars
    #
    for key in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"]:
        os.environ[key] = custom_ca_bundle
        set_env_vars.append(key)


@atexit.register
def deinit():
    """ Remove custom CA bundle at runtime exit """
    global custom_ca_bundle  # pylint: disable=W0603,C0103
    global set_env_vars  # pylint: disable=W0603,C0103
    #
    if custom_ca_bundle is not None and os.path.exists(custom_ca_bundle):
        try:
            os.remove(custom_ca_bundle)
        except:  # pylint: disable=W0702
            pass
    #
    custom_ca_bundle = None
    for key in set_env_vars:
        os.environ.pop(key, None)
