#! /usr/bin/env python

import os
import sys
import argparse
import logging
import subprocess
import re
from functools import wraps


DESCRIPTION = """
Scan and bring up a wifi interface.
"""

VT100_MAGENTA = b'\x1b[35m'
VT100_CYAN = b'\x1b[36m'
VT100_RESET = b'\x1b[0m'


def main(args = sys.argv[1:]):
    opts = parse_args(args)

    with InterfaceLifetime(opts.interface):
        entry = scan_and_select_entry(opts.interface, opts.all)
        dhcproc = associate_to_access_point(opts.interface, entry)
        wait_for_dhclient(dhcproc)


def with_log(f):
    log = logging.getLogger(f.__name__)
    @wraps(f)
    def g(*a, **kw):
        return f(log, *a, **kw)
    return g


@with_log
def parse_args(log, args):
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

    p.add_argument('--all',
                   dest='all',
                   default=False,
                   action='store_true',
                   help='Show all APs, even those requiring encryption.')

    opts = p.parse_args(args)

    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname) 5s %(name)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z',
        level=getattr(logging, opts.loglevel))

    log.debug('Options: %r', opts)
    return opts


@with_log
def run(log, *args, **kw):
    log.info('Running: %r %r', args, kw)
    return subprocess.check_call(args, **kw)


@with_log
def gather_output(log, *args, **kw):
    log.info('Running: %r %r', args, kw)
    return subprocess.check_output(args, **kw)


def scan_and_select_entry(iface, all):
    if all:
        do_scan = scan
    else:
        do_scan = lambda iface: list(filter_out_encrypted_entries(scan(iface)))

    entries = do_scan(iface)

    while True:
        print '\nEntries:\n  q) quit\n  r) rescan\n'
        display_table( [e.as_display_list() for e in entries] )

        command = raw_input('? ')
        if command == 'r':
            print 'Rescanning...'
            entries = do_scan(iface)
            continue
        elif command == 'q':
            raise SystemExit('Bye!')
        else:
            try:
                ix = int(command)
                entry = entries[ix]
            except ValueError:
                print 'I did not understand %r' % (command,)
                continue
            except IndexError:
                print 'Not a valid selection %r' % (command,)
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

    entries.sort(key = lambda e: e.get_field('essid'))

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

    def get_field(self, name, default=None):
        return self.fields.get(name, default)

    def set_field(self, name, value):
        assert name in self._fields and self._fields[name] is None, \
            `name, value, self._fields`
        self._fields[name] = value


def display_table(rows, f=sys.stdout):
    collens = [ max( [len(x) for x in col] ) for col in zip(*rows) ]

    for (i, row) in enumerate(rows):
        assert len(collens) == len(row), `collens, row`

        f.write( VT100_CYAN if i % 6 > 2 else VT100_MAGENTA )
        f.write('% 3d)' % (i,))

        for (collen, cell) in zip(collens, row):
            padlen = collen - len(cell)
            f.write(' %s%s' % (' ' * padlen, cell))

        f.write(VT100_RESET)
        f.write('\n')


@with_log
def filter_out_encrypted_entries(log, entries):
    for entry in entries:
        log.debug('Considering %r to filter; encrypted %r...', entry, entry.encrypted)
        if not entry.encrypted:
            yield entry


def associate_to_access_point(iface, entry):
    if entry.encrypted:
        raise NotImplementedError('encrypted wifi for %r' % (entry,))
    else:
        run('iwconfig', iface,
            'ap', entry.address,
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
        log.info('dhclient exited (%x, %x): %s', status, 2**15 + status, describe_process_status(status))


def describe_process_status(status):
    if os.WIFEXITED(status):
        return 'exited with status {!r}'.format(os.WEXITSTATUS(status))
    elif os.WIFSIGNALED(status):
        return 'terminated by signal {!r}'.format(os.WTERMSIG(status))
    elif os.WIFSTOPPED(status):
        return 'stopped with signal {!r}'.format(os.WSTOPSIG(status))
    elif os.WIFCONTINUED(status):
        return 'continued'
    else:
        raise AssertionError('Unknown status format: {!r}'.format(status))


class InterfaceLifetime (object):
    def __init__(self, iface):
        self._iface = iface

    def __enter__(self):
        run('ifconfig', self._iface, 'up')
        return None

    def __exit__(self, etype, ev, etb):
        run('ifconfig', self._iface, 'down')
        return False


if __name__ == '__main__':
    main()
