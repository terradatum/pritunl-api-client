#!/bin/env python

import argparse

from pritunl import *

# pri = Pritunl(url='https://pritunl.terradatum.com',
#               token='2frwRPLuZd2RdNjHSeza4SdxJNVB6CBh',
#               secret='3fwa0f9E0Z6yNUM6zT83XwqjAVMMQrix')

parser = argparse.ArgumentParser('pritunl-api-client')
parser.add_argument('--url', '-u', dest='url',
                    required=True,
                    type=str,
                    help='The pritunl API url',
                    metavar='URL')
parser.add_argument('--api-token', '-t', dest='token',
                    required=True,
                    type=str,
                    help='The pritunl admin API token',
                    metavar='TOKEN')
parser.add_argument('--api-secret', '-s', dest='secret',
                    required=True,
                    type=str,
                    help='The pritunl admin API secret',
                    metavar='SECRET')

subparsers = parser.add_subparsers(dest='subcommand')


def argument(*names_or_flags, **kwargs):
    return names_or_flags, kwargs


def subcommand(*subparser_args, parent=subparsers):
    def decorator(func):
        name = func.__name__.replace('_', '-')
        sub_parser = parent.add_parser(name, description=func.__doc__)
        for args, kwargs in subparser_args:
            sub_parser.add_argument(*args, **kwargs)
        sub_parser.set_defaults(func=func)

    return decorator


# noinspection PyUnusedLocal
@subcommand()
def get_status(args):
    """Get pritunl status"""
    if pri.ping():
        print(pri.status())


@subcommand()
def get_org(args):
    """Get the Org"""
    if pri.ping():
        print(pri.organization.get())


@subcommand(
    argument('--org', '-o', help='The org id'),
    argument('--user', '-u', help='The user id')
)
def get_user(args):
    """Get User(s) by Org Id or User Id"""
    if pri.ping():
        print(pri.user.get(args.org, args.user))


if __name__ == '__main__':
    args = parser.parse_args()

    pri = Pritunl(args.url, args.token, args.secret)

    if args.subcommand is None:
        args.print_help()
    else:
        args.func(args)
