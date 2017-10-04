#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Tool for log forwarding configuration on IPA servers and clients
# Copyright (C) 2015  Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import string
import sys

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from random import SystemRandom
from subprocess import call

from SSSDConfig import SSSDConfig


_CONFIG_RSYSLOG_CONF_DIR = '/etc/rsyslog.d'
_CONFIG_SSSD_CONF_FILE = '/etc/sssd/sssd.conf'


class ExternalCommandError(Exception):
    pass


class SSSD(object):
    """SSSD"""

    def __init__(self, config_file=_CONFIG_SSSD_CONF_FILE):
        self._sssdconfig = SSSDConfig()
        self._sssdconfig.import_config(config_file)

    def _get_service_objects(self):
        return [self._sssdconfig.get_service(service_name)
            for service_name in self._sssdconfig.list_services()]

    def _get_domain_objects(self):
        return [self._sssdconfig.get_domain(domain_name)
            for domain_name in self._sssdconfig.list_domains()]

    def _debug_all_services(self, debug_level, leave_higher=True):
        for srv in self._get_service_objects():
            if leave_higher and 'debug_level' in srv.options \
                    and srv.options['debug_level'] >= debug_level:
                continue
            srv.set_option('debug_level', debug_level)
            self._sssdconfig.save_service(srv)

    def _debug_all_domains(self, debug_level, leave_higher=True):
        for dom in self._get_domain_objects():
            if leave_higher and 'debug_level' in dom.options \
                    and dom.options['debug_level'] >= debug_level:
                continue
            dom.set_option('debug_level', debug_level)
            self._sssdconfig.save_domain(dom)

    def _write(self):
        self._sssdconfig.write()

    def _restart(self):
        print 'Condrestarting SSSD'
        if call(['systemctl', 'condrestart', 'sssd']) != 0:
            raise ExternalCommandError('Failed to condrestart SSSD')

    def get_domains(self):
        domains = self._sssdconfig.list_domains()
        print 'SSSD domains: ' + ', '.join(domains)
        return domains

    def get_realms(self):
        realms = []
        for dom in self._get_domain_objects():
            if 'ipa_domain' in dom.options:
                realms.append(dom.options['ipa_domain'].upper())
            else:
                realms.append(dom.name.upper())
        print 'Realms: ' + ', '.join(realms)
        return realms

    def is_server(self):
        for dom in self._get_domain_objects():
            if 'ipa_server_mode' in dom.options \
                    and dom.options['ipa_server_mode']:
                print 'SSSD is running in server mode'
                return True
        print 'SSSD is running in client mode'
        return False

    def enable_debug(self, debug_level=2, leave_higher=True):
        print 'Setting SSSD debug level to ' + str(debug_level)
        self._debug_all_services(debug_level, leave_higher)
        self._debug_all_domains(debug_level, leave_higher)
        self._write()
        self._restart()


class Auditd(object):
    """Auditd"""

    _AUDITD_SYSLOG_CONF = '/etc/audisp/plugins.d/syslog.conf'

    def _restart(self):
        print 'Reloading auditd'
        if call(['systemctl', 'reload', 'auditd']) != 0:
            raise ExternalCommandError('Failed to reload auditd')

    def log_to_syslog(self):
        print 'Enabling audisp syslog plugin'
        if call(['sed', '-i', 's/active = no/active = yes/',
                self._AUDITD_SYSLOG_CONF]) != 0:
            raise ExternalCommandError(
                'Failed to run sed on file: ' + self._AUDITD_SYSLOG_CONF)
        self._restart()

    def revert(self):
        print 'Disabling audisp syslog plugin'
        if call(['sed', '-i', 's/active = yes/active = no/',
                self._AUDITD_SYSLOG_CONF]) != 0:
            raise ExternalCommandError(
                'Failed to run sed on file: ' + self._AUDITD_SYSLOG_CONF)
        self._restart()


class RequirementError(Exception):
    pass

class Requirements(object):
    """Check (and meet if possible) requirements for this script"""

    def check_rsyslog(self):
        if not os.path.isdir(_CONFIG_RSYSLOG_CONF_DIR):
            raise RequirementError('Rsyslog config directory "{0}" does not '
                'exist. Is rsyslog installed?'.format(_CONFIG_RSYSLOG_CONF_DIR))
        if not os.access(_CONFIG_RSYSLOG_CONF_DIR, os.W_OK):
            raise RequirementError('You do not have write permission to the '
                'rsyslog config directory "{0}". You probably need to run this '
                'script as root or with sudo.'.format(_CONFIG_RSYSLOG_CONF_DIR))

    def check_sssd(self):
        if not os.path.isfile(_CONFIG_SSSD_CONF_FILE):
            raise RequirementError('SSSD config file "{0}" does not exist. '
                'Does this machine belong to an IPA domain?'.format(
                _CONFIG_SSSD_CONF_FILE))

    def check_all(self):
        self.check_rsyslog()
        self.check_sssd()


class RsyslogError(Exception):
    pass

class Rsyslog(object):
    """Rsyslog"""

    _REMOTE_RULESET = 'remote_ipa_elastic'

    _STATIC_CONF_FILES = [
        '00.load-imfile-module',
        '00.remote-ipa-elastic-ruleset',
        '01.ipa-auditd',
        '01.ipa-authpriv',
        '01.ipa-httpd',
        '01.ipa-krb5',
        '01.ipa-389',
        '01.ipa-ca',
        '10.ipa-sssd-processes',
        '11.ipa-sssd-domains',
    ]

    _IMFILE_LOAD = 'module(load="imfile" pollingInterval="2")'

    _AUDITD_FORWARD_RULE = 'if ($syslogtag == "audispd:") then {{\n' \
        '  call {ruleset}\n' \
        '  stop\n' \
        '}}'

    _AUTHPRIV_FORWARD_RULE = 'if ($syslogfacility-text == "authpriv") ' \
        'then {{\n' \
        '  call {ruleset}\n' \
        '}}'

    _IMFILE_RULE_TEMPLATE = 'input(type="imfile"\n' \
        '  ruleset="{ruleset}"\n' \
        '  file="{log_file}"\n' \
        '  tag="{tag}")\n'

    _ELASTIC_REMOTE_RULESET_TEMPLATE = 'ruleset(name="{ruleset}") {{\n' \
        '  action(type="omfwd"\n' \
        '  target="{target}"\n' \
        '  port="514"\n' \
        '  protocol="tcp"\n' \
        '  queue.type="linkedlist"\n' \
        '  queue.size="4000"\n' \
        '  queue.dequeuebatchsize="200"\n' \
        '  queue.saveOnShutdown="on"\n' \
        '  action.resumeRetryCount="-1")\n' \
        '}}\n' \
        '$WorkDirectory /var/lib/rsyslog\n\n'

    _STATIC_LOG_DATA = {
        '/var/log/httpd/access_log':
            {'tag': 'httpdaccess', 'conf_file': '01.ipa-httpd'},
        '/var/log/httpd/error_log':
            {'tag': 'httpderror', 'conf_file': '01.ipa-httpd'},
        '/var/log/kadmind.log':
            {'tag': 'krb5-kadmin', 'conf_file': '01.ipa-krb5'},
        '/var/log/krb5kdc.log':
            {'tag': 'krb5-kdc', 'conf_file': '01.ipa-krb5'},
        '/var/log/pki/pki-tomcat/ca/transactions':
            {'tag': 'ipa-ca-transaction', 'conf_file': '01.ipa-ca'},
        '/var/log/sssd/sssd.log':
            {'tag': '-monitor', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/krb5_child.log':
            {'tag': '-krb5-child', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/ldap_child.log':
            {'tag': '-ldap-child', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/selinux_child.log':
            {'tag': '-selinux-child', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/gpo_child.log':
            {'tag': '-gpo-child', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_nss.log':
            {'tag': '-nss', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_pam.log':
            {'tag': '-pam', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_pac.log':
            {'tag': '-pac', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_autofs.log':
            {'tag': '-autofs', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_ssh.log':
            {'tag': '-ssh', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_sudo.log':
            {'tag': '-sudo', 'conf_file': '10.ipa-sssd-processes'},
        '/var/log/sssd/sssd_ifp.log':
            {'tag': '-ifp', 'conf_file': '10.ipa-sssd-processes'},
    }

    def _create_conf_file_full_path(self, f):
        if not f in self._get_conf_files():
            raise RsyslogError('Invalid rsyslog config file: {0}'.format(f))
        return '{0}/{1}.conf'.format(_CONFIG_RSYSLOG_CONF_DIR, f)

    def _get_conf_files(self):
        return self._STATIC_CONF_FILES

    def _get_conf_files_full_path(self):
        return [self._create_conf_file_full_path(f)
            for f in self._get_conf_files()]

    def _create_imfile_rule(self, log_file, tag):
        state_file = '{0}-{1}'.format(tag, ''.join(SystemRandom().choice(
            string.ascii_letters + string.digits) for _ in range(3)))
        return self._IMFILE_RULE_TEMPLATE.format(ruleset=self._REMOTE_RULESET,
            log_file=log_file, tag=tag, state_file=state_file)

    def _get_log_data(self):
        logs = self._STATIC_LOG_DATA
        sssd = SSSD()
        sssd_server = sssd.is_server()
        to_remove = []
        # Add sssd domain logs
        for d in sssd.get_domains():
            logs['/var/log/sssd/sssd_{0}.log'.format(d)] = \
                {'tag': '-domain', 'conf_file': '11.ipa-sssd-domains'}
        # Add 389 logs according to the current realms
        for r in sssd.get_realms():
            log_dir = '/var/log/dirsrv/slapd-{0}/'.format(r.replace('.', '-'))
            logs[log_dir + 'access'] = \
                {'tag': 'ipa-389-access', 'conf_file': '01.ipa-389'}
            logs[log_dir + 'audit'] = \
                {'tag': 'ipa-389-audit', 'conf_file': '01.ipa-389'}
            logs[log_dir + 'errors'] = \
                {'tag': 'ipa-389-errors', 'conf_file': '01.ipa-389'}
        for f, v in logs.iteritems():
            # Process tags for sssd
            if f.startswith('/var/log/sssd/'):
                if sssd_server:
                    logs[f]['tag'] = 'sssd-server' + v['tag']
                else:
                    logs[f]['tag'] = 'sssd' + v['tag']
            # Filter log data for non-existent log files. Skip sssd logs
            # as sssd is on both, server and client.
            else:
                if not os.path.isfile(f):
                    to_remove.append(f)
        for f in to_remove:
            print 'Rsyslog: skipping "{0}", log file not found.'.format(f)
            del logs[f]
        return logs

    def _write_imfile_load(self):
        cfpath = self._create_conf_file_full_path('00.load-imfile-module')
        print 'Rsyslog: enabling imfile module [{0}]'.format(cfpath)
        with open(cfpath, 'w') as cf:
            cf.write(self._IMFILE_LOAD)

    def _write_auditd_fwd_rule(self):
        cfpath = self._create_conf_file_full_path('01.ipa-auditd')
        print 'Rsyslog: forwarding auditd logs to remote ruleset [{0}]'.format(
            cfpath)
        with open(cfpath, 'w') as cf:
            cf.write(self._AUDITD_FORWARD_RULE.format(
                ruleset=self._REMOTE_RULESET))

    def _write_authpriv_fwd_rule(self):
        cfpath = self._create_conf_file_full_path('01.ipa-authpriv')
        print 'Rsyslog: forwarding authpriv logs to remote ruleset ' \
            '[{0}]'.format(cfpath)
        with open(cfpath, 'w') as cf:
            cf.write(self._AUTHPRIV_FORWARD_RULE.format(
                ruleset=self._REMOTE_RULESET))

    def _write_elastic_remote_rule(self, target):
        cfpath = self._create_conf_file_full_path(
            '00.remote-ipa-elastic-ruleset')
        print 'Rsyslog: creating ruleset for forwarding logs [{0}]'.format(
            cfpath)
        with open(cfpath, 'w') as cf:
            cf.write(self._ELASTIC_REMOTE_RULESET_TEMPLATE.format(
                ruleset=self._REMOTE_RULESET, target=target))

    def _restart(self):
        print 'Enabling and restarting rsyslog service.'
        if call(['systemctl', 'enable', 'rsyslog']) != 0:
            raise ExternalCommandError('Failed to enable rsyslog service')
        if call(['systemctl', 'restart', 'rsyslog']) != 0:
            raise ExternalCommandError('Failed to restart rsyslog service')

    def _clean_config(self):
        config_files = self._get_conf_files_full_path()
        print 'Rsyslog: cleaning up config files:\n  ' + \
            '\n  '.join(config_files)
        for f in config_files:
            try:
                os.remove(f)
            except OSError:
                #print 'Could not remove file "{0}": {1}'.format(f, e)
                pass

    def write_config(self, target):
        self._clean_config()
        self._write_imfile_load()
        self._write_elastic_remote_rule(target)
        self._write_auditd_fwd_rule()
        self._write_authpriv_fwd_rule()
        for f, v in self._get_log_data().iteritems():
            cfpath = self._create_conf_file_full_path(v['conf_file'])
            print 'Rsyslog: including "{0}" log [{1}]'.format(f, cfpath)
            with open(cfpath, 'a') as cf:
                cf.write(self._create_imfile_rule(f, v['tag']))
        self._restart()

    def revert(self):
        self._clean_config()
        self._restart()


def main():
    """Entry-point for script"""

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
        description='Configure log forwarding on IPA servers and clients\nto '
            'the remote server.',
        epilog=os.path.basename(__file__) + '  Copyright (C) 2015  '
            'Red Hat, Inc.\nThis program comes with ABSOLUTELY NO WARRANTY.\n'
            'This is free software, and you are welcome to redistribute it\n'
            'under certain conditions; see LICENSE file for details.')
    parser.add_argument('-t', '--target',
        help='destination address of target central logging server. Can be '
            'either a domain name or IP address')
    parser.add_argument('-r', '--revert', action='store_true',
        help='revert configuration done by this script - return to the '
            'default state')
    args = parser.parse_args()

    if not args.target and not args.revert:
        print 'One of the --target or --revert options must be specified'
        sys.exit(1)
    elif args.target and args.revert:
        print 'Only one of the --target or --revert option can be specified'
        sys.exit(1)

    try:
        Requirements().check_all()
        if args.target:
            SSSD().enable_debug()
            Auditd().log_to_syslog()
            Rsyslog().write_config(args.target)
            print 'Configuration completed successfully, IPA logs are ' \
                'forwarded to ' + args.target
        elif args.revert:
            SSSD().enable_debug(1, False)
            Auditd().revert()
            Rsyslog().revert()
            print 'Configuration successfully reverted to the default state'
    except RequirementError as e:
        print 'Failed requirement: ' + str(e)
        sys.exit(1)
    except ExternalCommandError as e:
        print 'Failed to execute external command: ' + str(e)
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
