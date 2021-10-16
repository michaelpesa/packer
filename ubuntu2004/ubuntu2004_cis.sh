#!/usr/bin/env bash

set -e

PLATFORM="${1,,}"
case "$PLATFORM" in
  aws)
    TMP_OPTS="strictatime,nodev,nosuid"
    GRUB_CFG="/boot/grub/grub.cfg"
    ;;
  vmware)
    TMP_OPTS="strictatime,noexec,nodev,nosuid"
    GRUB_CFG="/boot/efi/EFI/ubuntu/grub.cfg"
    ;;
  *)
    echo "unsupported platform: $PLATFORM"
    exit 1
    ;;
esac

# 1.1.1.1 through 1.1.1.7
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
  echo "install $fs /bin/true" >> /etc/modprobe.d/cis.conf
  lsmod | grep $fs && rmmod $fs
done

# 1.1.3 through 1.1.5
cat > /etc/systemd/system/tmp.mount <<EOF
[Unit]
Description=Temporary Directory
Documentation=man:hier(7)
Documentation=http://www.freedesktop.org/wiki/Software/systemd/APIFileSystems
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,$TMP_OPTS

# Make 'systemctl enable tmp.mount' work:
[Install]
WantedBy=local-fs.target
EOF
systemctl daemon-reload

# 1.1.7 through 1.1.9
#sed -i -E 's|(tmpfs\s+/dev/shm\s+tmpfs\s+)defaults(.*)|\1defaults,nodev,nosuid,noexec,seclabel\2|' /etc/fstab
echo 'tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,seclabel 0 0' >> /etc/fstab

# 1.1.12 through 1.1.14
sed -i -E 's|(\S+\s+/var/tmp\s+\S+\s+)defaults(.*)|\1defaults,nodev,nosuid,noexec\2|' /etc/fstab

# 1.1.18 Ensure /home partition includes the nodev option
sed -i -E 's|(\S+\s+/home\s+\S+\s+)defaults(.*)|\1defaults,nodev\2|' /etc/fstab

# 1.3.1 Ensure AIDE is installed
export DEBIAN_FRONTEND=noninteractive
apt update
apt -y install aide aide-common
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 1.3.2 Ensure filesystem integrity is regularly checked
echo '0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check' | crontab -

# 1.4.1 Ensure permissions on bootloader config are not overridden
sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig

# 1.4.3 Ensure permissions on bootloader config are configured
chown root:root "${GRUB_CFG}"
chmod 0400 "${GRUB_CFG}"

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled
echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/50-cis.conf

# 1.5.4 Ensure core dumps are restricted
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/50-cis.conf
echo '* hard core 0' >> /etc/security/limits.d/50-cis.conf
systemctl disable --now apport

# 1.6.1.1 Ensure AppArmor is installed
apt -y install apparmor apparmor-utils

# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub

# 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
aa-enforce /etc/apparmor.d/* || /bin/true

# 1.7.2 Ensure local login warning banner is configured properly
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue

# 1.7.3 Ensure local login warning banner is configured properly
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net

# 1.7.4 Ensure permissions on /etc/motd are configured
[[ -f /etc/motd ]] && (chown root:root /etc/motd; chmod 644 /etc/motd)

# 1.7.5 Ensure permissions on /etc/issue are configured
chown root:root /etc/issue
chmod 0644 /etc/issue

# 1.7.6 Ensure permissions on /etc/issue.net are configured
chown root:root /etc/issue.net
chmod 0644 /etc/issue.net

# 1.9 Ensure updates, patches, and additional security software are installed
apt -y -s upgrade

# 2.1.1.3 Ensure chrony is configured
apt -y install chrony
cat > /etc/chrony/chrony.conf <<EOF
server time.google.com iburst minpoll 8

user _chrony

# This directive specify the location of the file containing ID/key pairs for
# NTP authentication.
keyfile /etc/chrony/chrony.keys

# This directive specify the file into which chronyd will store the rate
# information.
driftfile /var/lib/chrony/chrony.drift

# Uncomment the following line to turn logging on.
log tracking measurements statistics

# This directive forces 'chronyd' to send a message to syslog if it
# makes a system clock adjustment larger than a threshold value in seconds.

logchange 0.5

# Log files location.
logdir /var/log/chrony

# Stop bad estimates upsetting machine clock.
maxupdateskew 100.0

# This directive enables kernel synchronisation (every 11 minutes) of the
# real-time clock. Note that it can’t be used along with the 'rtcfile' directive.
rtcsync

# Step the system clock instead of slewing it if the adjustment is larger than
# one second, but only in the first three clock updates.
makestep 1 3
EOF

systemctl restart chrony
systemctl enable chrony

# 2.1.2 Ensure X Window System is not installed
apt -y purge xserver-xorg*

# 2.1.15 Ensure mail transfer agent is configured for local-only mode
apt -y install postfix
sed -i 's/^inet_interfaces =.*/inet_interfaces = localhost/' /etc/postfix/main.cf
systemctl restart postfix
systemctl enable postfix

# 2.2.4 Ensure telnet client is not installed
apt -y purge telnet

# 3.1.1 Disable IPv6
echo 'AddressFamily inet' >> /etc/ssh/sshd_config
sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 ipv6.disable=1"/' /etc/default/grub

# 3.2.1 Ensure packet redirect sending is disabled
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.d/50-cis.conf

# 3.2.2 Ensure IP forwarding is disabled
echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/50-cis.conf

# 3.3.1 Ensure source routed packets are not accepted
echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.d/50-cis.conf

# 3.3.2 Ensure ICMP redirects are not accepted
echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/50-cis.conf

# 3.3.3 Ensure secure ICMP redirects are not accepted
echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.d/50-cis.conf

# 3.3.4 Ensure suspicious packets are logged
echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/50-cis.conf

# 3.3.5 Ensure broadcast ICMP requests are ignored
echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/50-cis.conf

# 3.3.6 Ensure bogus ICMP resposnes are ignored
echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.d/50-cis.conf

# 3.3.7 Ensure bogus ICMP resposnes are ignored
echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/50-cis.conf
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/50-cis.conf

# 3.3.8 Ensure TCP SYN Cookies is enabled
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/50-cis.conf

sysctl -p
sysctl -w net.ipv4.route.flush=1

# Ensure TCP Wrappers is installed
# This isn't present in the latest benchmark, keeping it for compatibility
apt -y install tcpd

# 3.4.1 Ensure DCCP is disabled
# 3.4.2 Ensure SCTP is disabled
# 3.4.2 Ensure RDS is disabled
# 3.4.2 Ensure TIPC is disabled
cat >> /etc/modprobe.d/cis.conf <<EOF
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

if [ $PLATFORM == "vmware" ]; then
  # 3.5.1.1 Ensure ufw is installed
  apt -y install ufw
  
  # 3.5.1.2 Ensure iptables-persistent is not installed with ufw
  apt -y purge iptables-persistent
  
  # 3.5.1.3 Ensure ufw service is enabled
  ufw allow proto tcp from any to any port 22
  ufw --force enable
  
  # 3.5.1.4 Ensure ufw loopback traffic is configured
  ufw allow in on lo
  ufw allow out on lo
  ufw deny in from 127.0.0.0/8
  
  # 3.5.1.5 Ensure ufw outbound connections are configured
  ufw allow out on all
fi

# 4.1.1.1 Ensure auditd is installed
apt -y install auditd audispd-plugins

# 4.1.1.2 Ensure auditd service is enabled
systemctl enable --now auditd

# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled
# 4.1.1.4 Ensure audit_backlog_limit is sufficient
sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
update-grub

# 4.1.2.1 Ensure audit log storage size is configured
sed -i 's/max_log_file\s+=.*/max_log_file = 10/' /etc/audit/auditd.conf

# 4.1.2.2 Ensure audit logs are not automatically deleted
#sed -i 's/max_log_file\s+=.*/max_log_file = 10/' /etc/audit/auditd.conf

# 4.1.3 Ensure events that modify date and time information are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

# 4.1.4 Ensure events that modify user/group information are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF

# 4.1.5 Ensure events that modify the system's network environment are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
EOF

# 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF

# 4.1.7 Ensure login and logout events are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF

# 4.1.8 Ensure session initiation information is collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF

# 4.1.9 Ensure discretionary access control permission modification events are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF

# 4.1.11 Ensure use of privileged commands is collected
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/50-cis.rules

# 4.1.12 Ensure successful file system mounts are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF

# 4.1.13 Ensure file deletion events by users are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF

# 4.1.14 Ensure changes to system administration scope (sudoers) is collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

# 4.1.15 Ensure system administrator command executions (sudo) are collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions
EOF

# 4.1.16 Ensure kernel module loading and unloading is collected
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

# Ensure system administrator actions (sudolog) are collected
# This isn't present in the latest benchmark, keeping it for compatibility
cat >> /etc/audit/rules.d/50-cis.rules <<EOF
-w /var/log/sudo.log -p wa -k actions
EOF

# 4.1.17 Ensure the audit configuration is immutable
echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules

# 4.2.2.1 Ensure journald is configured to send logs to rsyslog
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf

# 4.2.2.2 Ensure journald is configured to compress large log files
echo "Compress=yes" >> /etc/systemd/journald.conf

# 4.2.2.2 Ensure journald is configured to write logfiles to persistent disk
echo "Storage=persistent" >> /etc/systemd/journald.conf

# 5.1.2 through 5.1.7
for file in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  chown root:root $file
  chmod og-rwx $file
done

# 5.1.8 Ensure cron is restricted to authorized users
[[ -f /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow

# 5.1.9 Ensure at is restricted to authorized users
[[ -f /etc/at.deny ]] && rm /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

# 5.2.2 Ensure sudo commands use pty
sed -i '/secure_path/a Defaults use_pty' /etc/sudoers

# 5.2.2 Ensure sudo commands use pty
sed -i '/use_pty/a Defaults logfile="/var/log/sudo.log"' /etc/sudoers

# 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod 0600 /etc/ssh/sshd_config

# 5.3.2 Ensure permissions on SSH private host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;

# 5.3.3 Ensure permissions on SSH public host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

# 5.3.5 Ensure SSH LogLevel is appropriate
grep -q "^LogLevel" /etc/ssh/sshd_config && sed -i 's/LogLevel\s.*/LogLevel VERBOSE/' /etc/ssh/sshd_config || echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

# 5.3.6 Ensure SSH X11 forwarding is disabled
grep -q "^X11Forwarding" /etc/ssh/sshd_config && sed -i 's/X11Forwarding\s.*/X11Forwarding no/' /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config

# 5.3.7 Ensure SSH MaxAuthTries is set to 4 or less
grep -q "^MaxAuthTries" /etc/ssh/sshd_config && sed -i 's/MaxAuthTries\s.*/MaxAuthTries 4/' /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config

# 5.3.8 Ensure SSH IgnoreRhosts is enabled
grep -q "^IgnoreRhosts" /etc/ssh/sshd_config && sed -i 's/IgnoreRhosts\s.*/IgnoreRhosts yes/' /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

# 5.3.9 Ensure SSH HostbasedAuthentication is disabled
grep -q "^HostbasedAuthentication" /etc/ssh/sshd_config && sed -i 's/HostbasedAuthentication\s.*/HostbasedAuthentication no/' /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config

# 5.3.10 Ensure SSH root login is disabled
grep -q "^PermitRootLogin" /etc/ssh/sshd_config && sed -i 's/PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config

# 5.3.11 Ensure PermitEmptyPasswords is disabled
grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config && sed -i 's/PermitEmptyPasswords\s.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

# 5.3.12 Ensure PermitUserEnvironment is disabled
grep -q "^PermitUserEnvironment" /etc/ssh/sshd_config && sed -i 's/PermitUserEnvironment\s.*/PermitUserEnvironment no/' /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

# 5.3.13 Ensure only strong Ciphers are used
SSHD_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
grep -q "^Ciphers" /etc/ssh/sshd_config && sed -i "s/Ciphers\s.*/Ciphers ${SSHD_CIPHERS}/" /etc/ssh/sshd_config || echo "Ciphers ${SSHD_CIPHERS}" >> /etc/ssh/sshd_config

# 5.3.14 Ensure only strong MAC algorithms are used
SSHD_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
grep -q "^MACs" /etc/ssh/sshd_config && sed -i "s/MACs\s.*/MACs ${SSHD_MACS}/" /etc/ssh/sshd_config || echo "MACs ${SSHD_MACS}" >> /etc/ssh/sshd_config

# 5.3.15 Ensure only strong Key Exchange algorithms are used
SSHD_KEX_ALGORITHMS="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
grep -q "^KexAlgorithms" /etc/ssh/sshd_config && sed -i "s/KexAlgorithms\s.*/KexAlgorithms ${SSHD_KEX_ALGORITHMS}/" /etc/ssh/sshd_config || echo "KexAlgorithms ${SSHD_KEX_ALGORITHMS}" >> /etc/ssh/sshd_config

# 5.3.16 Ensure SSH Idle Timeout Interval is configured
grep -q "^ClientAliveInterval" /etc/ssh/sshd_config && sed -i "s/ClientAliveInterval\s.*/ClientAliveInterval 300/" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config && sed -i "s/ClientAliveCountMax\s.*/ClientAliveCountMax 3/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config

# 5.3.17 Ensure SSH LoginGraceTime is set to one minute or less
grep -q "^LoginGraceTime" /etc/ssh/sshd_config && sed -i "s/LoginGraceTime\s.*/LoginGraceTime 60/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config

# 5.3.18 Ensure SSH warning banner is configured
grep -q "^Banner" /etc/ssh/sshd_config && sed -i "s/Banner\s.*/Banner \/etc\/issue.net/" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

# 5.3.19 Ensure SSH PAM is enabled
grep -q "^UsePAM" /etc/ssh/sshd_config && sed -i "s/UsePAM\s.*/UsePAM yes/" /etc/ssh/sshd_config || echo "UsePAM yes" >> /etc/ssh/sshd_config

# 5.3.20 Ensure SSH AllowTcpForwarding
grep -q "^AllowTcpForwarding" /etc/ssh/sshd_config && sed -i "s/AllowTcpForwarding\s.*/AllowTcpForwarding no/" /etc/ssh/sshd_config || echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config

# 5.3.21 Ensure SSH MaxStartups is configured
grep -q "^MaxStartups" /etc/ssh/sshd_config && sed -i "s/MaxStartups\s.*/MaxStartups 10:30:60/" /etc/ssh/sshd_config || echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config

# 5.3.22 Ensure SSH MaxSessions is configured
grep -q "^MaxSessions" /etc/ssh/sshd_config && sed -i "s/MaxSessions\s.*/MaxSessions 10/" /etc/ssh/sshd_config || echo "MaxSessions 10" >> /etc/ssh/sshd_config

# 5.3.22 Ensure SSH MaxSessions is configured
grep -q "^MaxSessions" /etc/ssh/sshd_config && sed -i "s/MaxSessions\s.*/MaxSessions 10/" /etc/ssh/sshd_config || echo "MaxSessions 10" >> /etc/ssh/sshd_config

systemctl restart sshd

# 5.4.1 Ensure password creation requirements are configured
apt -y install libpam-pwquality
cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
sed -i '/pam_deny.so/a password        requisite                       pam_pwquality.so retry=3' /etc/pam.d/common-password

# 5.4.3 Ensure password reuse is limited
sed -i '/pam_permit.so/a password        required                       pam_pwhistory.so remember=5' /etc/pam.d/common-password

# 5.5.1.1 Ensure minimum days between password changes is configured
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs

# 5.5.1.2 Ensure password expiration is 365 days or less
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs

# 5.5.1.3 Ensure password expiration warning days is 7 more
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# 5.5.1.1 through 5.5.1.3, for existing users
awk -F: '$2 ~ !"*" && $2 ~ !"!!" {print $1}' /etc/shadow | while read user; do
  chage --mindays 1 $user
  chage --maxdays 365 $user
  chage --warndays 7 $user
done

# 5.5.4 Ensure default user umask is 027 or more restrictive
echo "umask 027" > /etc/profile.d/set_umask.sh
echo -e "\numask 027" >> /etc/bash.bashrc

# 5.5.5 Ensure default user shell timeout is 900 seconds or less
echo "readonly TMOUT=900 ; export TMOUT" > /etc/profile.d/set_tmout.sh

# 5.7 Ensure access to the su command is restricted
groupadd sugroup
sed -i -E 's/#\sauth\s+required\s+pam_wheel.so/auth       required pam_wheel.so use_uid group=sugroup/' /etc/pam.d/su

# 6.2.6 Ensure users' home directories permissions are 750 or more restrictive
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do
  if [ -d "$dir" ]; then
    dirperm=$(stat -L -c "%A" "$dir")
    if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
        chmod g-w,o-rwx "$dir"
    fi
  fi
done

