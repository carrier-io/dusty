#!/usr/bin/python3
# coding=utf-8

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
    Logging tool: Loki support (dusty adoption)
"""

import json
import gzip
import time
import logging
import logging.handlers
import traceback
import threading
import requests  # pylint: disable=E0401


class CarrierLokiLogEmitter:  # pylint: disable=R0902
    """ Emit logs to Loki """

    def __init__(  # pylint: disable=R0913
            self, loki_push_url,
            loki_user=None, loki_password=None, loki_token=None,
            default_labels=None,
            verify=False, retries=3, retry_delay=0.5, timeout=15,
        ):
        self.loki_push_url = loki_push_url
        self.loki_user = loki_user
        self.loki_password = loki_password
        self.loki_token = loki_token
        #
        self.default_labels = default_labels if default_labels is not None else dict()
        #
        self.verify = verify
        self.retries = retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        #
        self._connection = None

    def connect(self):
        """ Get connection object """
        if self._connection is not None:
            return self._connection
        #
        self._connection = requests.Session()
        #
        if self.loki_user is not None and self.loki_password is not None:
            self._connection.auth = (self.loki_user, self.loki_password)
        if self.loki_token is not None:
            self._connection.headers.update({
                "Authorization": f"Bearer {self.loki_token}",
            })
        #
        self._connection.headers.update({
            "Content-Type": "application/json",
            # "Content-Encoding": "gzip",
        })
        #
        return self._connection

    def disconnect(self):
        """ Destroy connection object """
        if self._connection is not None:
            try:
                self._connection.close()
            except:  # pylint: disable=W0702
                pass
            self._connection = None

    def post_data(self, data):
        """ Do a POST to Loki """
        for _ in range(self.retries):
            try:
                connection = self.connect()
                # payload = gzip.compress(json.dumps(data).encode("utf-8"))
                payload = json.dumps(data).encode("utf-8")
                response = connection.post(
                    self.loki_push_url, data=payload, verify=self.verify, timeout=self.timeout,
                )
                response.raise_for_status()
                return response
            except:  # pylint: disable=W0702
                self.disconnect()
                time.sleep(self.retry_delay)

    def emit_line(self, unix_epoch_in_nanoseconds, log_line, additional_labels=None):
        """ Emit log line """
        labels = self.default_labels
        if additional_labels is not None:
            labels.update(additional_labels)
        #
        data = {
            "streams": [
                {
                    "stream": labels,
                    "values": [
                        [f"{unix_epoch_in_nanoseconds}", log_line],
                    ]
                }
            ]
        }
        #
        self.post_data(data)

    def emit_batch(self, batch_data, additional_labels=None):
        """ Emit log line """
        labels = self.default_labels
        if additional_labels is not None:
            labels.update(additional_labels)
        #
        data = {
            "streams": [
                {
                    "stream": labels,
                    "values": batch_data,
                }
            ]
        }
        #
        self.post_data(data)
        #
        # TODO: batches with different stream labels (a.k.a. multiple streams support)


class CarrierLokiLogHandler(logging.Handler):
    """ Log handler - send logs to storage """

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        #
        default_loki_labels = self.settings.get("labels", dict())
        #
        self.emitter = CarrierLokiLogEmitter(
            loki_push_url=self.settings.get("url"),
            loki_user=self.settings.get("user", None),
            loki_password=self.settings.get("password", None),
            loki_token=self.settings.get("token", None),
            default_labels=default_loki_labels,
            verify=self.settings.get("verify", False),
            # retries=3,
            # retry_delay=0.5,
            # timeout=15,
        )

    def handleError(self, record):
        """ Handle error while logging """
        super().handleError(record)
        self.emitter.disconnect()

    def emit(self, record):
        try:
            record_ts = int(record.created * 1000000000)
            record_data = self.format(record)
            #
            additional_labels = dict()
            if self.settings.get("include_level_name", True):
                additional_labels["level"] = record.levelname
            if self.settings.get("include_logger_name", True):
                additional_labels["logger"] = record.name
            #
            self.emitter.emit_line(record_ts, record_data, additional_labels)
        except:  # pylint: disable=W0702
            # In this case we should NOT use logging to log logging error. Only print()
            print("[FATAL] Exception during sending logs")
            traceback.print_exc()


class CarrierLokiBufferedLogHandler(logging.handlers.BufferingHandler):
    """ Log handler - buffer and send logs to storage """

    def __init__(self, settings):
        super().__init__(
            settings.get("buffer_capacity", 100)
        )
        self.settings = settings
        #
        default_loki_labels = self.settings.get("labels", dict())
        #
        self.emitter = CarrierLokiLogEmitter(
            loki_push_url=self.settings.get("url"),
            loki_user=self.settings.get("user", None),
            loki_password=self.settings.get("password", None),
            loki_token=self.settings.get("token", None),
            default_labels=default_loki_labels,
            verify=self.settings.get("verify", False),
            # retries=3,
            # retry_delay=0.5,
            # timeout=15,
        )
        #
        self.last_flush = 0.0
        PeriodicFlush(self, self.settings.get("buffer_flush_deadline", 30)).start()

    def handleError(self, record):
        """ Handle error while logging """
        super().handleError(record)
        self.emitter.disconnect()

    def shouldFlush(self, record):
        """ Check if we need to flush messages """
        return \
            (len(self.buffer) >= self.capacity) or \
            (time.time() - self.last_flush) >= self.settings.get("buffer_flush_interval", 10)

    def flush(self):
        self.acquire()
        try:
            log_records = list()
            while self.buffer:
                record = self.buffer.pop(0)
                record_ts = int(record.created * 1000000000)
                record_data = self.format(record)
                # TODO: batches with different stream labels (a.k.a. multiple streams support)
                log_records.append([f"{record_ts}", record_data])
            if log_records:
                self.emitter.emit_batch(log_records)
        except:  # pylint: disable=W0702
            # In this case we should NOT use logging to log logging error. Only print()
            print("[FATAL] Exception during sending logs to manager")
            traceback.print_exc()
        finally:
            self.release()
            self.last_flush = time.time()


class PeriodicFlush(threading.Thread):  # pylint: disable=R0903
    """ Flush logger time to time """

    def __init__(self, handler, interval=30):
        super().__init__(daemon=True)
        self.handler = handler
        self.interval = interval

    def run(self):
        """ Run handler thread """
        while True:
            time.sleep(self.interval)
            self.handler.flush()
