#!/usr/bin/env python
import binascii
import socket
import threading
import time
import os
import logging

from kubernetes import client, config
from enum import Enum

from .VERSION import Version

logger = logging.getLogger("utils")
logger.setLevel(logging.INFO)


class TLSPaths(Enum):
    cert_dir = "/etc/certs"
    tls_crt = os.path.join(cert_dir, "tls.crt")
    tls_key = os.path.join(cert_dir, "tls.key")
    client_cert_dir = "/etc/cacert"
    client_tls_crt = os.path.join(client_cert_dir, "tls.crt")

def kube_v1():
    # Assume we got nothin'.
    k8s_api = None

    # XXX: is there a better way to check if we are inside a cluster or not?
    if "KUBERNETES_SERVICE_HOST" in os.environ:
        # If this goes horribly wrong and raises an exception (it shouldn't),
        # we'll crash, and Kubernetes will kill the pod. That's probably not an
        # unreasonable response.
        config.load_incluster_config()
        k8s_api = client.CoreV1Api()
    else:
        # Here, we might be running in docker, in which case we'll likely not
        # have any Kube secrets, and that's OK.
        try:
            config.load_kube_config()
            k8s_api = client.CoreV1Api()
        except FileNotFoundError:
            # Meh, just ride through.
            logger.info("No K8s")
            pass

    return k8s_api

class SystemInfo (object):
    MyHostName = socket.gethostname()
    MyResolvedName = socket.gethostbyname(socket.gethostname())

class RichStatus (object):
    def __init__(self, ok, **kwargs):
        self.ok = ok
        self.info = kwargs
        self.info['hostname'] = SystemInfo.MyHostName
        self.info['resolvedname'] = SystemInfo.MyResolvedName
        self.info['version'] = Version

    # Remember that __getattr__ is called only as a last resort if the key
    # isn't a normal attr.
    def __getattr__(self, key):
        return self.info.get(key)

    def __bool__(self):
        return self.ok

    def __nonzero__(self):
        return bool(self)
        
    def __contains__(self, key):
        return key in self.info

    def __str__(self):
        attrs = ["%s=%s" % (key, self.info[key]) for key in sorted(self.info.keys())]
        astr = " ".join(attrs)

        if astr:
            astr = " " + astr

        return "<RichStatus %s%s>" % ("OK" if self else "BAD", astr)

    def toDict(self):
        d = { 'ok': self.ok }

        for key in self.info.keys():
            d[key] = self.info[key]

        return d

    @classmethod
    def fromError(self, error, **kwargs):
        kwargs['error'] = error
        return RichStatus(False, **kwargs)

    @classmethod
    def OK(self, **kwargs):
        return RichStatus(True, **kwargs)

class SourcedDict (dict):
    def __init__(self, _source="--internal--", _from=None, **kwargs):
        super().__init__(self, **kwargs)

        if _from and ('_source' in _from):
            self['_source'] = _from['_source']
        else:
            self['_source'] = _source

        # self['_referenced_by'] = []

    def _mark_referenced_by(self, source):
        refby = self.setdefault('_referenced_by', [])

        if source not in refby:
            refby.append(source)

class DelayTrigger (threading.Thread):
    def __init__(self, onfired, timeout=5, name=None):
        super().__init__()

        if name:
            self.name = name

        self.trigger_source, self.trigger_dest = socket.socketpair()

        self.onfired = onfired
        self.timeout = timeout

        self.setDaemon(True)
        self.start()

    def trigger(self):
        self.trigger_source.sendall(b'X')

    def run(self):
        while True:
            self.trigger_dest.settimeout(None)
            x = self.trigger_dest.recv(128)

            self.trigger_dest.settimeout(self.timeout)

            while True:
                try:
                    x = self.trigger_dest.recv(128)
                except socket.timeout:
                    self.onfired()
                    break


class PeriodicTrigger(threading.Thread):
    def __init__(self, onfired, period=5, name=None):
        super().__init__()

        if name:
            self.name = name

        self.onfired = onfired
        self.period = period

        self.daemon = True
        self.start()

    def trigger(self):
        pass

    def run(self):
        while True:
            time.sleep(self.period)
            self.onfired()


def read_cert_secret(secret_name):
    namespace = os.environ.get('AMBASSADOR_NAMESPACE', 'default')
    k8s_api = kube_v1()
    cert_data = None
    cert = None
    key = None

    try:
        cert_data = k8s_api.read_namespaced_secret(secret_name, namespace)
    except client.rest.ApiException as e:
        if e.reason == "Not Found":
            pass
        else:
            logger.info("secret %s/%s could not be read: %s" % (namespace, secret_name, e))

    if cert_data and cert_data.data:
        cert_data = cert_data.data
        cert = cert_data.get('tls.crt', None)

        if cert:
            cert = binascii.a2b_base64(cert)

        key = cert_data.get('tls.key', None)

        if key:
            key = binascii.a2b_base64(key)

    return cert, key, cert_data


def save_cert(cert, key, dir):
    try:
        os.makedirs(dir)
    except FileExistsError:
        pass

    open(os.path.join(dir, "tls.crt"), "w").write(cert.decode("utf-8"))

    if key:
        open(os.path.join(dir, "tls.key"), "w").write(key.decode("utf-8"))
