#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401

#   Copyright 2021 getcarrier.io
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
    Events
"""

from dusty.tools import log

from arbiter.eventnode import MockEventNode


class EventManager:
    """ Events """

    def __init__(self):
        self.node = MockEventNode()

    def subscribe(self, event, callback):
        """" Subscribe to event """
        log.debug("Adding event subscription: event=%s, callback=%s", event, callback)
        self.node.subscribe(event, callback)

    def unsubscribe(self, event, callback):
        """" Unsubscribe from event """
        log.debug("Removing event subscription: event=%s, callback=%s", event, callback)
        self.node.unsubscribe(event, callback)

    def emit(self, event, data=None):
        """ Emit event with data """
        log.debug("Emitting event: event=%s, data=%s", event, data)
        self.node.emit(event, data)
