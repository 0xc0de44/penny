#!/usr/bin/python3

from vulnerability import *
from port import *
from device import *


class Model:
    class _Model:
        def __init__(self):
            self.devices = {}

        def addDevice(self, ip, os=None, version=None):
            d = Device(ip, os, version)
            self.devices[ip] = d

        def addPortToIp(self, ip, port):
            if ip not in self.devices.keys():
                return False
            self.devices[ip].addPort(port)
            return True

        def addVulnerabilityToPort(self, ip, portnum, vuln, type, desc, links):
            if ip not in self.devices.keys() or portnum not in self.devices[ip].ports.keys():
                return False
            p=self.devices[ip].ports[portnum]
            v=Vulnerability()
            v.software=p.software
            v.version = p.version
            v.type = type
            v.desc = desc
            for l in links:
                v.addExploit(l)
            p.addVuln(v)
            return True

    instance = None

    def __init__(self):
        if not Model.instance:
            Model.instance = Model._Model()

    def __getattr__(self, name):
        return getattr(self.instance, name)


if __name__ == "__main__":
    print(f"### model.py ###\n")
