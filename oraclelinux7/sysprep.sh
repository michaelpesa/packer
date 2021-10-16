#!/bin/bash

# This will return the RHEL OS major version (ex. 7, 8)
VERSION="$(rpm -q --queryformat '%{RELEASE}' rpm | grep -o [[:digit:]]*\$)"

# Stop logging services (auditd can only be stopped using service, not systemctl)
service rsyslog stop
service auditd stop

# Clean up old kernel versions
case "$VERSION" in
  8) yum -y remove --oldinstallonly ;;
  7) package-cleanup --oldkernels --count=1 ;;
  *) echo "Unexpected OS version '$VERSION', exiting"; exit 1 ;;
esac
yum clean all

# Force rotate log files and remove any compressed log files
logrotate -f /etc/logrotate.conf
rm -f /var/log/*.gz
# Remove rotated logs (ex. /var/log/cron-20210317)
find /var/log -type f -regextype posix-extended -regex '.*/[a-z]+-[0-9]+' -exec rm -f {} \;
# Remove installer logs
rm -rf /var/log/anaconda

# Truncate log files
> /var/log/wtmp
> /var/log/lastlog
> /var/log/audit/audit.log

# Remove SSH host keys
rm -f /etc/ssh/*key*

# Clean up /root
rm -f /root/anaconda-ks.cfg /root/original-ks.cfg /root/ks.log
rm -rf '/root/~awx'

# Clear history
unset HISTFILE
rm -f /root/.bash_history
history -c sys-unconfig

