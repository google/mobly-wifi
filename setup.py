# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Installs Mobly WiFi Module."""

import setuptools

description = (
    'Mobly WiFi controller module for using Python code to operate network '
    'devices in Mobly tests.'
)

install_requires = [
    'mobly>=1.12.2',
    'immutabledict',
    'paramiko>=2.10.4',
    'pyzmq>=15.0.0',
    'packaging',
]

setuptools.setup(
    name='mobly-wifi',
    version='1.1b2',
    author='Minghao Li',
    author_email='minghaoli@google.com',
    description=description,
    license='Apache2.0',
    url='https://github.com/google/mobly-wifi',
    packages=setuptools.find_namespace_packages(
        include=['mobly.controllers.*']
    ),
    package_data={'mobly.controllers.wifi': ['data/*']},
    install_requires=install_requires,
    python_requires='>=3.11',
)
