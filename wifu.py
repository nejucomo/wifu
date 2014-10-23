#! /usr/bin/env python

import sys
import argparse
import logging
import subprocess
import re
from functools import wraps


DESCRIPTION = """
Scan and bring up a wifi interface.
"""


def main(args = sys.argv[1:]):
    opts = parse_args(args)
    run('sudo', 'ifconfig', opts.interface, 'up')
    entries = scan(opts.interface)
    for entry in entries:
        print entry


def parse_args(args):
    p = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('--log-level',
                   dest='loglevel',
                   default='DEBUG', #'INFO',
                   choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                   help='Set logging level.')

    p.add_argument('--interface', '-i',
                   dest='interface',
                   default='wlan0',
                   help='Wifi interface.')

    opts = p.parse_args(args)

    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname) 5s %(name)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z',
        level=getattr(logging, opts.loglevel))

    return opts


def with_log(f):
    log = logging.getLogger(f.__name__)
    @wraps(f)
    def g(*a, **kw):
        return f(log, *a, **kw)
    return g


@with_log
def run(log, *args, **kw):
    log.info('Running: %r %r', args, kw)
    return subprocess.check_call(args, **kw)


@with_log
def gather_output(log, *args, **kw):
    log.info('Running: %r %r', args, kw)
    return subprocess.check_output(args, **kw)


@with_log
def scan(log, iface):
    return parse_scan_output(
        gather_output('sudo', 'iwlist', iface, 'scan'))


@with_log
def parse_scan_output(log, output):
    entries = []

    for line in output.split('\n')[1:]:
        log.debug('Parsing line: %r', line)
        m = parse_scan_output._EntryRgx.match(line)
        if m is None:
            log.debug('No match.')
            continue

        if m.group('address') is not None:
            if entries:
                assert entries[-1].finalized, str(entries[-1])
            entries.append(ScanEntry())
            log.debug('New entry.')

        entry = entries[-1]

        for (key, value) in m.groupdict().iteritems():
            if value is not None:
                entry.set_field(key, value)
                log.debug('Set %r: %s', key, entry)

    entries.sort(key = lambda e: e.essid)

    return entries

parse_scan_output._EntryRgx = re.compile(
    r'''
    ^(
      [ ]{10}Cell \s \d+ \s - \s Address: \s
          (?P<address>
            [A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:
            [A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}
          )
    | [ ]{20} (
      | Channel:(?P<channel>\d+)
      | Quality=(?P<quality>\d+/\d+) \s+
          Signal \s level=(?P<siglevel>-?\d+ \s dBm) \s{2}
      | ESSID:"(?P<essid>[^"]*)"
      | Encryption \s key:(?P<encryption>on|off)
      )
    )$
    ''',
    re.VERBOSE)


class ScanEntry (object):
    def __init__(self):
        keys = 'address essid channel encryption quality siglevel'.split()
        self._fields = dict( (k, None) for k in keys)

    @property
    def finalized(self):
        for v in self._fields.itervalues():
            if v is None:
                return False
        return True

    def __str__(self):
        return ('{address} ch:{channel} '
                'enc:{encryption} Q:{quality} sig:{siglevel} {essid!r}'
            ).format(**self._fields)

    def __getattr__(self, name):
        return self._fields[name]

    def set_field(self, name, value):
        assert name in self._fields and self._fields[name] is None, \
            `name, value, self._fields`
        self._fields[name] = value


if __name__ == '__main__':
    main()
