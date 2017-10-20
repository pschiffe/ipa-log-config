# ipa-log-config

A tool for log forwarding configuration on IPA servers and clients. Configures rsyslog to collect and forward selected log files to desired remote server. For more information about this effort and some inspiration what can be done with those logs, visit [this page](https://www.freeipa.org/page/Centralized_Logging).

## Usage

```
# ./ipa_log_config.py --target <domain name or ip of target server>
```

To revert changes done by this script, use the `--revert` option:

```
# ./ipa_log_config.py --revert
```

## Supported platforms

Currently, only RHEL 7 / CentOS 7 and derivates are supported.

## Requirements

The script requires `python2-sssdconfig` package.

## Detailed description

This tool tries to be as not invasive as possible. The rsyslog configuration is done in the separate files, which could be easily removed. Besides that, it configures debug level of SSSD and enables audisp syslog plugin. All logs are written to their original destination AND sent to the remote server, so no logs are lost from the local machine.

### Forwarded logs

```
/var/log/audit/audit.log
/var/log/secure
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/kadmind.log
/var/log/krb5kdc.log
/var/log/pki/pki-tomcat/ca/transactions
/var/log/dirsrv/slapd-<REALM>/access
/var/log/dirsrv/slapd-<REALM>/audit
/var/log/dirsrv/slapd-<REALM>/errors
/var/log/sssd/sssd.log
/var/log/sssd/krb5_child.log
/var/log/sssd/ldap_child.log
/var/log/sssd/selinux_child.log
/var/log/sssd/gpo_child.log
/var/log/sssd/sssd_nss.log
/var/log/sssd/sssd_pam.log
/var/log/sssd/sssd_pac.log
/var/log/sssd/sssd_autofs.log
/var/log/sssd/sssd_ssh.log
/var/log/sssd/sssd_sudo.log
/var/log/sssd/sssd_ifp.log
/var/log/sssd/sssd_<DOMAIN>.log
```

Most of the logs are forwarded using rsyslog imfile module. The only exceptions are audit and secure logs. Audit is sent to rsyslog using audisp syslog plugin and secure log is written directly by rsyslog, so only forwarding is added for this one. 
