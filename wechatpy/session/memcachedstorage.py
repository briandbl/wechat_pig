# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from wechatpy.session import SessionStorage
from wechatpy._compat import json


class MemcachedStorage(SessionStorage):

    def __init__(self, mc, prefix='wechatpy'):
        for method_name in ('get', 'set', 'delete'):
            assert hasattr(mc, method_name)
        self.mc = mc
        self.prefix = prefix

    def key_name(self, key):
        return '{0}:{1}'.format(self.prefix, key)

    def get(self, key):
        key = self.key_name(key)
        value = self.mc.get(key)
        if not value:
            return None
        try:
            return json.loads(value)
        except ValueError:
            return value

    def set(self, key, value, ttl=None):
        if value is None:
            return
        key = self.key_name(key)
        value = json.dumps(value)
        self.mc.set(key, value)

    def delete(self, key):
        key = self.key_name(key)
        self.mc.delete(key)