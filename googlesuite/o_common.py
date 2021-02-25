# -*- coding: utf-8 -*-

import binascii
import json
import logging
import os
import pipes
import pwd
import re
import socket
import string
import struct
import sys
import time
import unicodedata

from collections import Counter, Mapping, OrderedDict
from datetime import datetime
from argparse import Action, Namespace
from argparse import SUPPRESS as AP_SUPPRESS
from json import JSONEncoder
from logging.handlers import SysLogHandler
from random import SystemRandom
from urlparse import urlparse
from uuid import UUID
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, SUPPRESS

import psycopg2.errorcodes
import requests
import tldextract

from lxml import etree as lxml_etree
from natsort import natsorted, ns
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError
from sortedcontainers import SortedDict, SortedList, SortedListWithKey, SortedSet

# GLOBALS #

script_name = os.path.basename(os.path.realpath(__file__))
script_directory = os.path.dirname(os.path.realpath(__file__))
build_directory = os.path.realpath(os.path.join(script_directory, '..'))
data_directory = os.path.realpath(os.path.join(build_directory, 'data'))

log = logging.getLogger(__name__)

DB_DEFAULT = "service='scheduler'"
DB_OSINT = "service='osint'"
DB_KEY_FILE = '/usr/local/arceo/.db_key'
DB_KEY_VAR = os.environ.get('DB_KEY')
API_KEY_FILE = '/usr/local/arceo/.api_key'
API_KEY_VAR = os.environ.get('API_KEY')
KEY_CHARS = string.ascii_letters + string.digits
KEY_LENGTH = 48
ENCODING = 'utf-8'
SENTINEL = 'SENTINEL'
VALID_CHARS = '-_.()%s%s' % (string.ascii_letters, string.digits)

RE_INT = re.compile('^[0-9]+$', re.IGNORECASE)
RE_ISO_8601 = re.compile(r'[:]|([-](?!((\d{2}[:]\d{2})|(\d{4}))$))', re.IGNORECASE)
RE_DELIMITER = re.compile(r'[/.]', re.IGNORECASE)
RE_MULTI_SPACE = re.compile(r'\s{2,}', re.IGNORECASE)
RE_NEWLINES = re.compile(r'\r?\n', re.IGNORECASE)
RE_START_SPACE = re.compile(r'^\s*$', re.IGNORECASE)

RE_UPPER_LOWER = re.compile(r'(.)([A-Z][a-z]+)')
RE_LOWER_UPPER = re.compile(r'([a-z0-9])([A-Z])')

NATSORT_ALG = (ns.IGNORECASE | ns.UNSIGNED | ns.LOCALE)

OK_STATUS = (requests.codes.ok, requests.codes.created, requests.codes.accepted, requests.codes.no_content)
rest_client = requests.Session()
http_backend = requests.adapters.HTTPAdapter(max_retries=0)
https_backend = requests.adapters.HTTPAdapter(max_retries=0)
rest_client.mount('http://', http_backend)
rest_client.mount('https://', https_backend)


# LOGGING #

class SyslogHandler(SysLogHandler):
    def __init__(self, tag='unknown', **kwargs):
        super(SyslogHandler, self).__init__(**kwargs)
        self.tag = '%s[%s]: ' % (tag, os.getpid())

    def emit(self, record):
        try:
            priority = '<%d>' % self.encodePriority(self.facility, self.mapPriority(record.levelname))
            local_time = time.localtime(record.created)
            raw_day = local_time.tm_mday
            day = ' ' + str(raw_day) if raw_day <= 9 else str(raw_day)
            rfc_3164 = time.strftime("%b %%s %H:%M:%S ", time.localtime(time.time())) % day
            message = self.format(record) + '\000'

            if isinstance(message, unicode):
                message = message.encode('utf-8')

            data = '%s%s%s%s' % (priority, rfc_3164, self.tag, message)
            # limit the maximum size of the message
            data = data[0:32768]

            if self.unixsocket:
                try:
                    self.socket.send(data)
                except socket.error:
                    self.socket.close()  # See issue 17981
                    self._connect_unixsocket(self.address)
                    self.socket.send(data)
            elif self.socktype == socket.SOCK_DGRAM:
                self.socket.sendto(data, self.address)
            else:
                self.socket.sendall(data)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


def logging_init(script_name, tag, facility='local1', level=logging.INFO, stream=sys.stderr):
    logging.basicConfig(
        format='%(asctime)s: ' + script_name + ': %(levelname)s: %(message)s',
        level=level,
        stream=stream)
    if os.path.exists('/dev/log') and not os.environ.get('DYNO'):
        handler = SyslogHandler(tag=tag, address='/dev/log', facility=facility)
        handler.formatter = logging.root.handlers[0].formatter
        logging.root.addHandler(handler)


def logging_level(args):
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.root.setLevel(level)


# ARGUMENT PARSING #

class KVAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        k, v = values
        params = getattr(namespace, 'params', {})
        params[k] = v
        setattr(namespace, 'params', params)


class DictNamespace(Namespace):
    def __init__(self, **kwargs):
        super(DictNamespace, self).__init__(**kwargs)

    def __len__(self):
        return len(vars(self))

    def __getitem__(self, key):
        value = vars(self).get(key, SENTINEL)
        if value is SENTINEL:
            raise KeyError()
        return value

    def get(self, key, default=None):
        return vars(self).get(key, default)

    def setdefault(self, key, default=None):
        return vars(self).setdefault(key, default)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __delitem__(self, key):
        delattr(self, key)

    def __iter__(self):
        return vars(self).__iter__()

    def iterkeys(self):
        return vars(self).__iter__()

    def keys(self):
        return vars(self).keys()

    def values(self):
        return [vars(self)[k] for k in self.keys()]

    def items(self):
        return [(k, vars(self)[k]) for k in self.keys()]

    def iteritems(self):
        return ((k, vars(self)[k]) for k in self.keys())

    def itervalues(self):
        return (vars(self)[k] for k in self.keys())

    def __reversed__(self):
        return reversed(self.keys())

    def __contains__(self, item):
        return item in vars(self)

    def clear(self):
        return vars(self).clear()

    def update(self, other):
        return vars(self).update(other)


def get_source(parser, action):
    for source in action.option_strings:
        if not source.startswith('--'):
            continue
        return source.lstrip(parser.prefix_chars).replace('-', '_')
    return action.dest


def load_namespace(parser, prefix, namespace=None):
    actions = {get_source(parser, x): [x.dest, x.const, x.default, x.nargs, x.type] for x in parser._actions if
               x.dest is not AP_SUPPRESS}
    prefix_full = (prefix + '_') if prefix else ''
    namespace = namespace if namespace else Namespace()
    for k, v in os.environ.iteritems():
        if not k.startswith(prefix_full):
            continue
        k = k[len(prefix_full):].lower()
        dest, const, default, nargs, conversion = actions.get(k, [k, None, None, None, None])

        if const:
            value = const
        elif nargs in ['*', '+']:
            value = [x for x in v.split(':') if x]
        elif v and conversion:
            value = conversion(v)
        elif v:
            value = v
        elif default is not AP_SUPPRESS:
            value = default
        setattr(namespace, dest, value)
    log.debug('environment namespace: %s', json_dump(vars(namespace)))
    return namespace


def arguments_check(args, items, message='%s is required'):
    for x in items:
        if not getattr(args, x, None):
            raise ValueError(message % x)


def configure_verbose(verbose):
    try:
        from requests.packages import urllib3
        urllib3.disable_warnings()
    except Exception as e:
        log.info('could not disable https warnings', exc_info=True)

    if not verbose:
        return

    try:
        import httplib
        httplib.HTTPConnection.debuglevel = 1
        urllib3_log = logging.getLogger('requests.packages.urllib3')
        urllib3_log.setLevel(logging.DEBUG)
        urllib3_log.propagate = True
    except Exception as e:
        log.info('could not enable http debugging', exc_info=True)


# DATABASE #

def get_key(key_file):
    key_directory = os.path.dirname(key_file)
    generator = SystemRandom()

    if not os.path.exists(key_directory):
        os.makedirs(key_directory)

    passwd = pwd.getpwnam('CompanyName')
    uid, gid = passwd.pw_uid, passwd.pw_gid

    umask = os.umask(0)
    try:
        fd = os.open(key_file, os.O_RDWR | os.O_CREAT, 0600)
        os.fchmod(fd, 0600)
        os.fchown(fd, uid, gid)
    finally:
        os.umask(umask)

    with os.fdopen(fd, 'r+') as f:
        key = f.read().strip()

        if not key:
            key = ''.join(generator.choice(KEY_CHARS) for _ in xrange(KEY_LENGTH))
            f.write(key)
            f.write('\n')

        f.seek(0)
        key = f.read().strip()

    return key


def get_db_key():
    if DB_KEY_VAR:
        return DB_KEY_VAR
    else:
        return get_key(DB_KEY_FILE)


def get_api_key():
    if API_KEY_VAR:
        return API_KEY_VAR
    else:
        return get_key(API_KEY_FILE)


read_dbs, write_dbs = OrderedDict(), OrderedDict()


def get_db(database, read_only=False):
    global read_dbs, write_dbs
    dbs = read_dbs if read_only else write_dbs

    db = dbs.get(database)
    if not db:
        log.debug('connecting to database: %s', database)
        db = psycopg2.connect(database)
        if read_only:
            db.set_session(readonly=True, autocommit=True)
        dbs[database] = db

    return db


def db_query(database, query, cooked=True, *args, **kwargs):
    if args and kwargs:
        raise ValueError('use only one parameter type')
    real_args = args if args else kwargs
    level = logging.DEBUG if cooked else 1

    data = []

    db = get_db(database, read_only=True)

    cursor = None
    try:
        cursor = db.cursor()
        query_text = cursor.mogrify(query, real_args)
        log.log(level, 'begin executing:\n%s', query_text)

        cursor.execute(query, real_args)
        log.log(level, 'query returned %05d rows', cursor.rowcount)
        if cooked:
            columns = [col[0].lower() if col[0].isupper() else col[0] for col in cursor.description]
            for row in cursor:
                row = OrderedDict(zip(columns, row))
                data.append(row)
        else:
            data = cursor.fetchall()
    except (psycopg2.Error) as e:
        log.exception('exception querying database')
        raise
    finally:
        if cursor: cursor.close()

    # log.debug('complete data: %s', json_dump(data))

    return data


def db_execute(database, query, *args, **kwargs):
    if args and kwargs:
        raise ValueError('use only one parameter type')
    real_args = args if args else kwargs

    db = get_db(database)

    cursor = None
    try:
        cursor = db.cursor()
        query_text = cursor.mogrify(query, real_args)
        log.debug('begin executing:\n%s', query_text)

        cursor.execute('BEGIN')
        cursor.execute(query, real_args)
        db.commit()
        cursor.close()
    except Exception as e:
        db.rollback()
        if isinstance(e, KeyboardInterrupt): raise
        if getattr(e, 'pgcode', None) == psycopg2.errorcodes.UNIQUE_VIOLATION:
            log.info('execution failed: duplicate data')
        else:
            log.exception('execution failed: exception')
    finally:
        if cursor: cursor.close()

    return


# DATA DUMPING #

def human_sorted(x, **kwargs):
    return natsorted(x, alg=NATSORT_ALG, **kwargs)


def human_sorted_indices(x, **kwargs):
    return natsorted(xrange(len(x)), key=x.__getitem__, alg=NATSORT_ALG, **kwargs)


class CustomJsonEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return human_sorted(obj)
        if isinstance(obj, Namespace):
            return vars(obj)
        if isinstance(obj, (SortedList, SortedListWithKey, SortedSet)):
            return list(obj)
        if isinstance(obj, (CustomCounter, CustomDict, CustomRecord, SortedDict)):
            return OrderedDict(obj.iteritems())
        if isinstance(obj, UUID):
            return str(obj)

        return JSONEncoder.default(self, obj)


def json_dump(data, multi_line=True, **kwargs):
    json_kwargs = {
        'sort_keys': False if isinstance(data, (CustomCounter, CustomRecord, Counter, OrderedDict)) else True,
        'cls':       CustomJsonEncoder}
    json_kwargs.update(kwargs)
    if multi_line:
        json_kwargs['indent'] = 4
        json_kwargs['separators'] = (',', ': ')
    else:
        json_kwargs['separators'] = (', ', ': ')
    return json.dumps(data, **json_kwargs)


def json_parse(input):
    headers = ''

    if input[0] not in ['[', '{']:
        start = min([y for y in [input.find(x) for x in ['[', '{']] if y != -1] or [0])
        headers = input[0:start - 1]
        input = input[start:] if start else 'null'

    payload = json.loads(input, object_pairs_hook=OrderedDict)

    return payload, headers


# CUSTOM CONTAINERS #

def get_attrs(x):
    if hasattr(x, '__dict__'):
        return x.__dict__.keys()
    else:
        # slots only
        return []


def get_dir(x):
    attrs = set()

    if hasattr(x, '__bases__'):
        # x is a class
        klass = x
    else:
        # x is an instance
        if not hasattr(x, '__class__'):
            # slots
            return human_sorted(get_attrs(x))
        klass = x.__class__
        attrs.update(get_attrs(klass))

    for cls in klass.__bases__:
        attrs.update(get_attrs(cls))
        attrs.update(get_dir(cls))

    attrs.update(get_attrs(x))

    return human_sorted(attrs)


# Python dicts are a subclass of dict
# the JSON encoder steals serialization of dict, and iterates in the wrong order
class CustomDictBase(object):
    def __init__(self, **kwargs):
        self.__dict__['data'] = None
        self.__dict__['has_float_keys'] = kwargs.get('has_float_keys', False)

    def __len__(self):
        return self.data.__len__()

    def __bool__(self):
        return self.data.__bool__()

    def __getitem__(self, key):
        return self.data.__getitem__(key)

    def __getattr__(self, key):
        try:
            return self.data.__getitem__(key)
        except KeyError:
            raise AttributeError

    def get(self, key, default=None):
        return self.data.get(key, default)

    def setdefault(self, key, default=None):
        return self.data.setdefault(key, default)

    def __setitem__(self, key, value):
        return self.data.__setitem__(key, value)

    def __setattr__(self, key, value):
        return self.data.__setitem__(key, value)

    def __delitem__(self, key):
        return self.data.__delitem__(key)

    def __delattr__(self, key):
        return self.data.__delitem__(key)

    def keys(self):
        raise NotImplementedError()

    # iterate by max value, and ascending keys
    def __iter__(self):
        return (k for k in self.keys())

    def iterkeys(self):
        return (k for k in self.keys())

    def values(self):
        return [self.data[k] for k in self.keys()]

    def items(self):
        return [(k, self.data[k]) for k in self.keys()]

    def iteritems(self):
        return ((k, self.data[k]) for k in self.keys())

    def itervalues(self):
        return (self.data[k] for k in self.keys())

    def __reversed__(self):
        return reversed(self.keys())

    def __contains__(self, item):
        return item in self.data

    def clear(self):
        return self.data.clear()

    def update(self, other):
        return self.data.update(other)

    def __dir__(self):
        rv = get_dir(self)
        rv.extend(self.keys())
        return human_sorted(rv)

        # pop, popitem

        # def copy(self):
        #    return CustomCounter([k, v]


class CustomCounter(CustomDictBase):
    def __init__(self, **kwargs):
        super(CustomCounter, self).__init__(**kwargs)
        self.__dict__['data'] = Counter()

    def keys(self):
        if self.has_float_keys:
            return natsorted(self.data.keys(), key=lambda k: (k, self.data[k]), reverse=True, alg=NATSORT_ALG)
        else:
            return natsorted(self.data.keys(), key=lambda k: (-(self.data[k]), k), alg=NATSORT_ALG)


class CustomDict(CustomDictBase):
    def __init__(self, **kwargs):
        super(CustomDict, self).__init__(**kwargs)
        self.__dict__['data'] = {}

    def keys(self):
        return natsorted(self.data.keys(), key=lambda k: (k, self.data[k]), alg=NATSORT_ALG)


class CustomRecord(CustomDictBase):
    def __init__(self, items):
        super(CustomRecord, self).__init__()
        self.__dict__['data'] = {x[0]: x[1] for x in items}

    def keys(self):
        return natsorted(self.data.keys(), key=lambda k: (k, self.data[k]), alg=NATSORT_ALG)


# CONTAINER PROCESSING #

def chunked(items, n):
    chunk = []
    for i, x in enumerate(items):
        if (i and i % n == 0):
            yield chunk
            del chunk[:]
        chunk.append(x)
    if chunk:
        yield chunk
    else:
        return


def fetch(data, path):
    if isinstance(path, basestring):
        path = RE_DELIMITER.split(path)

    if isinstance(data, Mapping):
        result = data.get(path[0])
    else:
        if not RE_INT.match(str(path[0])):
            return None
        i = int(path[0])
        result = data[i] if len(data) > i else None

    if len(path) == 1:
        return result
    else:
        if result:
            return fetch(result, path[1:])
        else:
            return None


def store(data, path, dest):
    if isinstance(path, basestring):
        path = RE_DELIMITER.split(path)

    for item in path[:-1]:
        dest = dest.setdefault(item, OrderedDict())

    dest[path[-1]] = data


def uniq(items):
    seen = {}
    result = []
    for item in items:
        if item in seen:
            continue
        seen[item] = True
        result.append(item)
    return result


def grouped(iterable, n):
    return izip(*[iter(iterable)] * n)


# DATA VALIDATION #

def try_int(x, default=SENTINEL):
    default = x if default is SENTINEL else default
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def try_float(x, default=SENTINEL):
    default = x if default is SENTINEL else default
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def force_int(x):
    try:
        return int(x)
    except:
        if x:
            return -1
        elif x is None:
            return None
        else:
            return 0


def positive_int(x):
    x = int(x)
    if x < 1:
        raise ValueError('value must be a positive integer')
    return x


def port_split(x):
    return [int(y) for y in x.split(',')]


def to_unix(x):
    rv = RE_NEWLINES.sub('\n', x).strip()
    if rv: rv += '\n'
    return rv


def strip_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def fix_name(name):
    name = RE_UPPER_LOWER.sub(r'\1-\2', name)
    name = RE_LOWER_UPPER.sub(r'\1-\2', name)
    name = name.lower()
    return name


def safe_file_name(file_name):
    # strip off whitespace
    file_name = file_name.strip()
    # strip off path
    file_name = os.path.basename(file_name)
    # delete international codepoints
    file_name = unicodedata.normalize('NFKD', unicode(file_name, 'utf-8')).encode('ASCII', 'ignore')
    # replace whitespace and punctuation
    file_name = ''.join(c if c in VALID_CHARS else '_' for c in file_name)
    # switch to standard delimiter
    file_name = re.sub(r'[-_]+', '_', file_name)
    # strip off extra delimiter(s)
    file_name = file_name.strip('_')

    return file_name


def safe_file_name_parts(file_name):
    file_name = safe_file_name(file_name)

    # fix extension
    file_name, extension = os.path.splitext(file_name)
    file_name = file_name or 'untitled'
    extension = extension or '.txt'

    return file_name, extension


def string_decode(x):
    return str(x.decode('ascii', 'ignore'))


def get_local_path(path):
    if not path.startswith('/'):
        path = os.path.join(os.getcwd(), path)
    return os.path.relpath(path, build_directory)


def is_valid_path(path, forced):
    if forced:
        return False
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    return (exists and size)


# DATE / TIME MANIPULATION #

def to_iso_format(ts):
    tm = time.gmtime(ts)
    iso = time.strftime('%Y-%m-%dT%H:%M:%S', tm)
    return iso


# XML PROCESSING #

def xml_time(d):
    return d.strftime('%Y-%m-%dT%H:%M:%SZ')


def xml_indent(element, level=0):
    i = '\n' + level * '  '
    if len(element):
        if not element.text or not element.text.strip():
            element.text = i + '  '
        if not element.tail or not element.tail.strip():
            element.tail = i
        for element in element:
            xml_indent(element, level + 1)
        if not element.tail or not element.tail.strip():
            element.tail = i
    else:
        if level and (not element.tail or not element.tail.strip()):
            element.tail = i


def xml_dump(element, indent=False):
    if indent: xml_indent(element)
    return lxml_etree.tostring(element, encoding=ENCODING, xml_declaration=False)


def fetch_paths(node, xpaths):
    paths = [x.strip() for x in xpaths.split(',')]
    values = [node.findtext(x) for x in paths]
    # for p, v in zip(paths, values):
    #    log.debug('p: %s, v: %s', p, v)
    return values


def fetch_xpaths(node, xpaths):
    paths = [x.strip() for x in xpaths.split(',')]
    values = [node.xpath(x)[0] for x in paths]
    # for x, v in zip(paths, values):
    #    log.debug('x: %s, v:\n%s', x, xml_dump(v))
    return values


# NETWORKING #

def get_dns(host):
    try:
        return socket.gethostbyaddr(host)[0] or None
    except socket.herror as e:
        # log.exception('could not get dns for host: [%s]' % host)
        log.warning('could not get dns for host: [%s]' % host)
        return None


ping_hosts = [
    # our hosts
    'www.yoursitename.com',
    'www.yoursitename.net',
    'apt.yoursitename.net',
    # other hosts
    'www.google.com',
    'www.facebook.com',
    'www.yahoo.com',
    'www.amazon.com',
]


def icmp_ping(hosts=ping_hosts):
    results = OrderedDict()
    for host in hosts:
        rv = os.system('ping -c 2 %s' % pipes.quote(host))
        result = 'failed' if rv else 'succeeded'
        results[host] = result
    log.info('icmp ping results:\n%s', json_dump(results))
    return results


def get_ip_from_hex(hex):
    if len(hex) == 8:
        value = struct.unpack('=I', binascii.unhexlify(hex))[0]
        ip = IPAddress(value, version=4)
    elif len(hex) == 32:
        words = struct.unpack('=IIII', binascii.unhexlify(hex))
        packed = struct.pack('!IIII', *words)
        value = socket.inet_ntop(socket.AF_INET6, packed)
        ip = IPAddress(value, version=6)

    ip_str = str(ip)
    log.debug('ip: %s', ip_str)
    return ip_str


def get_port_from_hex(hex):
    return int(hex, 16)


SSH_BANNER = 'SSH'
RECEIVE_TIMEOUT = 5
RECEIVE_LENGTH = 2048


def check_ssh_port(ip, port, key):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack('LL', RECEIVE_TIMEOUT, 0))

    rv = s.connect((ip, port))
    if rv:
        return False

    banner = ''
    try:
        banner = s.recv(RECEIVE_LENGTH)
    except socket.error as e:
        log.warn('ip: %s port: %s socket warning', ip, port, exc_info=True)
        return False

    log.debug('ip: %s port: %s banner: %s', ip, port, banner)

    if banner:
        return True if key in banner else False
    else:
        return False


def bracket_ip(x):
    return ('[' + x + ']') if ':' in x else x


def is_possible_ip(value):
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except:
        pass

    return False


def is_valid_ip(value, version=None):
    try:
        ip = IPAddress(value)
    except (ValueError, AddrFormatError):
        return False

    useless_ip_checks = [
        ip.is_loopback(),
        ip.is_reserved(),
        ip.is_link_local(),
        ip.is_private(),
        ip.is_multicast(),
        not ip.is_unicast(),
    ]
    if any(useless_ip_checks):            return False
    if ip.value == 0:                     return False
    if str(ip) == '255.255.255.255':      return False
    if version and ip.version != version: return False

    return True


def is_valid_cidr(value, version=None):
    try:
        cidr = IPNetwork(value)
        ip = cidr.ip
    except AddrFormatError:
        return False

    useless_ip_checks = [
        ip.is_loopback(),
        ip.is_reserved(),
        ip.is_link_local(),
        ip.is_private(),
        ip.is_multicast(),
        not ip.is_unicast(),
    ]
    if any(useless_ip_checks):            return False
    if ip.value == 0:                     return False
    if str(ip) == '255.255.255.255':      return False
    if version and ip.version != version: return False


tld_extractor = None


def is_valid_domain(value):
    global tld_extractor

    if not tld_extractor:
        cache_file = os.path.join(data_directory, 'tldextract_cache.pkl')
        tld_extractor = tldextract.TLDExtract(cache_file=cache_file, extra_suffixes=['i2p', 'onion'])

    extracted = tld_extractor(value)
    return bool(extracted.domain and extracted.suffix)


def get_domain(value_type, value):
    if value_type == 'domain':
        return value.lower()
    elif value_type == 'url':
        return urlparse(value).netloc.split(':')[0].lower()
    elif value_type == 'email':
        try:
            return value.split('@', 1)[1].lower()
        except IndexError:
            return ''
    else:
        return ''


HASH_LENGTHS = {
    'md5':    [32],
    'sha1':   [40],
    'sha256': [64],
    'sha512': [128],
}
HASH_LENGTHS['hash'] = [x[0] for x in HASH_LENGTHS.values()]


def get_value_type(value_type, value):
    if value_type in ['ipv4', 'ipv6']:
        return 'ip'
    elif value_type in ['ipv4_cidr', 'ipv6_cidr', 'cidr']:
        return 'cidr'
    elif value_type in ['domain', 'url', 'email']:
        return value_type
    elif value_type == 'hash':
        length = len(value)
        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        elif length == 128:
            return 'sha512'

    raise ValueError('invalid type %s and value %s' % (value_type, value))


def check_value_type(value_type, value):
    if value_type in ['ipv4', 'ipv6']:
        return is_valid_ip(value)
    elif value_type in ['ipv4_cidr', 'ipv6_cidr']:
        return is_valid_cidr(value)
    elif value_type == 'domain':
        return is_valid_domain(value)
    elif value_type in ['url', 'email']:
        domain = get_domain(value_type, value)
        if is_valid_domain(domain):
            return True
        elif is_valid_ip(domain):
            return True
        return False
    elif value_type in ['hash', 'md5', 'sha1', 'sha256', 'sha512']:
        try:
            _ = int(value, 16)
        except ValueError:
            return False
        return len(value) in HASH_LENGTHS.get(value_type, [])

    raise ValueError('invalid type %s and value %s' % (value_type, value))


def domain_partitions(domain):
    parents = []
    rlevels = domain.split('.')[::-1]
    for i in xrange(1, len(rlevels) + 1):
        parent = rlevels[0:i]
        parents.append('.'.join(parent[::-1]))
    return tuple(parents)


# XXX: add database parameter
def check_whitelist(value_type, value):
    rv, db = None, get_db(DB_OSINT, read_only=True)

    if value_type in ['ip', 'cidr', 'ipv4', 'ipv6', 'ipv4_cidr', 'ipv6_cidr']:
        rv = db_query(DB_OSINT,
                      "SELECT COALESCE(array_agg(id ORDER BY id), '{}') FROM osint_whitelist WHERE value_type ILIKE 'ip%%' AND (value = %(value)s OR network >>= %(value)s)",
                      cooked=False, value=value)[0][0]
    elif value_type == 'domain':
        # regular: block item and subdomains
        # google.com - block
        # www.google.com - block
        # something.else.google.com - block
        #
        # suffix:  block item and NOT subdomains
        # hacker.comcastbusiness.net - import
        # comcastbusiness.net - block
        # www.comcastbusiness.net - block
        if value.startswith('www.'):
            value = value[len('www.'):]

        rv = db_query(DB_OSINT,
                      "SELECT COALESCE(array_agg(id ORDER BY id), '{}') FROM osint_whitelist WHERE value_type = 'domain' AND (NOT is_suffix AND value IN %(partitions)s) OR (is_suffix AND value IN %(values)s)",
                      cooked=False, partitions=domain_partitions(value), values=(value, 'www.' + value))[0][0]
    elif value_type in ['url', 'email']:
        rv = []
        domain = get_domain(value_type, value)
        if is_valid_domain(domain):
            rv.extend(check_whitelist('domain', domain))
        elif is_valid_ip(domain):
            rv.extend(check_whitelist('ip', domain))
        current = db_query(DB_OSINT,
                           "SELECT COALESCE(array_agg(id ORDER BY id), '{}') FROM osint_whitelist WHERE value_type = %(value_type)s AND value = %(value)s",
                           cooked=False, value_type=value_type, value=value)[0][0]
        rv.extend(current)
    elif value_type in ['hash', 'md5', 'sha1', 'sha256', 'sha512']:
        rv = db_query(DB_OSINT,
                      "SELECT COALESCE(array_agg(id ORDER BY id), '{}') FROM osint_whitelist WHERE value_type LIKE %(value_type)s AND value = %(value)s",
                      cooked=False, value_type=value_type, value=value)[0][0]

    if rv is None:
        raise ValueError('invalid type %s and value %s' % (value_type, value))

    # level = logging.INFO if rv else logging.DEBUG
    if rv:
        log.info('whitelist check type: %-08s value: %-60s blocked_ids: %s', value_type, value,
                 ', '.join([str(x) for x in rv]) if rv else 'empty')

    return rv


# SYSTEM UTILITIES #

def check_root():
    if os.geteuid() == 0:
        return

    message = 'this program requires root privileges'
    logging.error(message)
    sys.exit(message)


class Command(object):
    ''' Base class for all commands '''

    def __init__(self, options):
        self.options = self.validate_options(options)
        self.log = logging.getLogger(self.get_name())

    def validate_options(self, options):
        'options can be dict / namespace / namedtuple'
        options_dict = options if isinstance(options, dict) else vars(options)
        for setting in self.get_arguments():
            value = options_dict.get(setting.name, setting.default)
            if not value and setting.required:
                raise ValueError('%s is required' % setting.name)
            value = setting.type(value)
            options_dict[setting.name] = value
        return DictNamespace(**options_dict)

    def run(self):
        'Runs the command'
        pass

    @classmethod
    def get_name(cls):
        return cls.__name__.lower()

    @classmethod
    def get_prefix(cls):
        return cls.get_name().upper()

    @classmethod
    def get_description(cls):
        return cls.get_name()

    @classmethod
    def get_syslog_facility(cls):
        return 'local0'

    @classmethod
    def get_arguments(cls):
        return []

    @classmethod
    def get_exit_code(cls, exception):
        return 1

    @classmethod
    def main(cls):
        cls.initialize_logging()
        try:
            command = cls.create_from_command_line()
            command.run()
            return 0
        except Exception as e:
            logging.exception(str(e))
            return cls.get_exit_code(e)

    @classmethod
    def initialize_logging(cls):
        logging_init(cls.get_name(), cls.get_name(), facility=cls.get_syslog_facility(), stream=sys.stdout)

    @classmethod
    def create_from_command_line(cls):
        parser = cls.create_arg_parser()
        namespace = load_namespace(parser, os.environ.get('PREFIX', cls.get_prefix()))
        options = parser.parse_args(namespace=namespace)
        logging_level(options)
        return cls(options)

    @classmethod
    def create_arg_parser(cls):
        parser = ArgumentParser(description=cls.get_description(), formatter_class=ArgumentDefaultsHelpFormatter,
                                add_help=False)
        cls.add_global_args(parser)
        cls.add_custom_args(parser)
        return parser

    @classmethod
    def add_global_args(cls, parser):
        parser.add_argument('-?', '--help', action='help', help='Show Help Message And Exit', default=SUPPRESS)
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable Debug Logging')

    @classmethod
    def add_custom_args(cls, parser):
        for argument in cls.get_arguments():
            arg_name = argument.name.replace('_', '-')
            if not argument.positional: arg_name = '--' + arg_name

            kwargs = dict(default=argument.default, help=argument.description)

            # action='store_true' and 'type' are incompatible
            if argument.type is bool:
                kwargs['action'] = 'store_true'
            else:
                kwargs['action'] = 'store'
                kwargs['type'] = argument.type

                # positional and 'required' are incompatible
            # if not argument.positional:
            #     kwargs['required'] = argument.required
            ## NOTE: Not enforcing parameters at the argparse level,
            ## since they may come in from environment variables.

            # pass kwargs directly to argparse
            kwargs.update(argument.kwargs)

            parser.add_argument(arg_name, **kwargs)

        return parser


class Argument(object):
    def __init__(self, name, description=None, default=None, type=str,
                 required=False, positional=False, **kwargs):
        'kwargs will be passed verbatim to ArgumentParser.add_argument'
        self.name = name
        self.description = description or name
        self.default = default
        self.type = type
        self.required = required
        self.positional = positional
        self.kwargs = kwargs