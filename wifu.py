#! /usr/bin/env python

import sys
import argparse
import logging
import subprocess


DESCRIPTION = """
Scan and bring up a wifi interface.
"""


def main(args = sys.argv[1:]):
    opts = parse_args(args)
    result = check_output('sudo', 'iwlist', opts.interface, 'scan')
    logging.debug('scan result: %r', result


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
    return subprocess.check_call(*args, **kw)


@with_log
def gather_output(log, *args, **kw):
    log.info('Running: %r %r', args, kw)
    return subprocess.check_output(*args, **kw)


if __name__ == '__main__':
    main()
