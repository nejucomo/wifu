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
    run('ifconfig', opts.interface, 'up')

    entry = scan_and_select_entry(opts.interface)
    dhcproc = associate_to_access_point(opts.interface, entry)

    wait_for_dhclient(dhcproc)
    run('ifconfig', opts.interface, 'down')


def parse_args(args):
    p = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('--log-level',
                   dest='loglevel',
                   default='INFO',
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


def scan_and_select_entry(iface):
    while True:
        entries = scan(iface)

        print '\nEntries:\n  q) quit\n  r) rescan\n'
        display_table( [e.as_display_list() for e in entries] )

        command = raw_input('? ')
        if command == 'r':
            continue
        elif command == 'q':
            raise SystemExit('Bye!')
        else:
            try:
                ix = int(command)
                entry = entries[ix]
            except ValueError:
                print 'I did not understand %r; rescanning...' % (command,)
                continue
            except IndexError:
                print 'Not a valid selection %r; rescanning...' % (command,)
                continue
            else:
                return entry


@with_log
def scan(log, iface):
    return parse_scan_output(
        gather_output('iwlist', iface, 'scan'))


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

    @property
    def encrypted(self):
        return self.encryption == 'on'

    def __repr__(self):
        return '<ScanEntry {!r}>'.format(self._fields)

    def as_display_list(self):
        return [
            self.address,
            repr(self.essid),
            self.channel,
            self.encryption,
            self.quality,
            self.siglevel,
            ]

    def __getattr__(self, name):
        v = self._fields[name]
        assert v is not None, 'Attribute not yet set: %r' % (name,)
        return v

    def set_field(self, name, value):
        assert name in self._fields and self._fields[name] is None, \
            `name, value, self._fields`
        self._fields[name] = value


def display_table(rows, f=sys.stdout):
    collens = [ max( [len(x) for x in col] ) for col in zip(*rows) ]

    for (i, row) in enumerate(rows):
        assert len(collens) == len(row), `collens, row`

        f.write('% 3d)' % (i,))

        for (collen, cell) in zip(collens, row):
            padlen = collen - len(cell)
            f.write(' %s%s' % (' ' * padlen, cell))

        f.write('\n')


def associate_to_access_point(iface, entry):
    if entry.encrypted:
        raise NotImplementedError('encrypted wifi for %r' % (entry,))
    else:
        run('iwconfig', iface,
            'essid', entry.essid,
            'channel', entry.channel)

        return subprocess.Popen(args=['dhclient', '-d', iface], shell=False)


@with_log
def wait_for_dhclient(log, dhcproc):
    try:
        status = dhcproc.wait()
    except KeyboardInterrupt:
        print
        log.info('Ctrl-C')
    else:
        log.info('dhclient exited with status %r = 0x%04x', status, status)


if __name__ == '__main__':
    main()
