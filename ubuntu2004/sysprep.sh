#!/usr/bin/env bash

# Stop logging services (auditd can only be stopped using service, not systemctl)
service rsyslog stop
service auditd stop

sudo apt -y autoremove --purge

# Force rotate log files and remove any compressed log files
logrotate -f /etc/logrotate.conf
rm -f /var/log/*.gz
# Remove rotated logs (ex. /var/log/cron-20210317)
find /var/log -type f -regextype posix-extended -regex '.*/[a-z]+-[0-9]+' -exec rm -f {} \;
# Remove installer logs
rm -f /var/log/cloud-init*

# Truncate log files
> /var/log/wtmp
> /var/log/lastlog
> /var/log/audit/audit.log

# Remove SSH host keys
rm -f /etc/ssh/*key*
cat > /etc/rc.local <<EOF
#!/bin/sh
test -e /etc/ssh/ssh_host_rsa_key || dpkg-reconfigure openssh-server
EOF
chmod +x /etc/rc.local

# Clear history
unset HISTFILE
rm -f /root/.bash_history
history -c sys-unconfig

# Remove netplan configuration
rm -f /etc/netplan/00-installer-config.yaml

