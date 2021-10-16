#!/bin/sh
set -e

AUDITD_RC_CONF_FILE=/etc/rc.conf.d/auditd
BLACKLISTD_RC_CONF_FILE=/etc/rc.conf.d/blacklistd
CLEARTMP_RC_CONF_FILE=/etc/rc.conf.d/cleartmp
IPFW_RC_CONF_FILE=/etc/rc.conf.d/ipfw
NETOPTIONS_RC_CONF_FILE=/etc/rc.conf.d/netoptions
ROUTING_RC_CONF_FILE=/etc/rc.conf.d/routing
SSHD_RC_CONF_FILE=/etc/rc.conf.d/sshd
SYSLOGD_RC_CONF_FILE=/etc/rc.conf.d/syslogd
VMWARE_GUESTD_RC_CONF_FILE=/usr/local/etc/rc.conf.d/vmware_guestd

# Set the time
service ntpdate onestart || true

# Update FreeBSD
freebsd-update --not-running-from-cron fetch install || true

# Upgrade packages
pkg upgrade -qy

# Install and configure AIDE
pkg install -qy aide
aide --init
mv /var/db/aide/databases/aide.db.new /var/db/aide/databases/aide.db
echo '0 5 * * * /usr/local/bin/aide --config /etc/aide/aide.conf --check' | crontab -

# Configure auditd
sysrc -f "$AUDITD_RC_CONF_FILE" auditd_enable=YES
sed -i '' -e 's/filesz:2M/filesz:20M/; s/expire-after:10M/expire-after:100M/' /etc/security/audit_control
sed -i '' -e 's/root:lo:no/root:lo,ad,ex,fc,fd,fm,fw,pc:no/' /etc/security/audit_user

# Disable weak SSH keys
sysrc -f "$SSHD_RC_CONF_FILE" sshd_ecdsa_enable=NO
rm -f /etc/ssh/ssh_host_ecdsa_key*

# Setup firewall
sysrc -f "$IPFW_RC_CONF_FILE" firewall_enable=YES
sysrc -f "$IPFW_RC_CONF_FILE" firewall_quiet=YES
sysrc -f "$IPFW_RC_CONF_FILE" firewall_type=workstation
sysrc -f "$IPFW_RC_CONF_FILE" firewall_myservices=ssh/tcp
sysrc -f "$IPFW_RC_CONF_FILE" firewall_allowservices=any
sysrc -f "$IPFW_RC_CONF_FILE" firewall_logdeny=YES

# Setup blacklistd
sysrc -f "$BLACKLISTD_RC_CONF_FILE" blacklistd_enable=YES
sysrc -f "$BLACKLISTD_RC_CONF_FILE" blacklistd_flags=-r
touch /etc/ipfw-blacklist.rc
chmod 0600 /etc/ipfw-blacklist.rc
sed -i '' -e 's/^#UseBlacklist no/UseBlacklist yes/' /etc/ssh/sshd_config
sed -i '' -e 's/ftpd -l$/ftpd -B -l/' /etc/inetd.conf

# Configure SSH server
sed -i '' -e 's/^#AllowAgentForwarding yes/AllowAgentForwarding no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#AllowTcpForwarding yes/AllowTcpForwarding no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#Compression delayed/Compression no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#ClientAliveCountMax 3/ClientAliveCountMax 2/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#LogLevel INFO/LogLevel VERBOSE/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#MaxAuthTries 6/MaxAuthTries 2/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#MaxSessions 10/MaxSessions 2/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#UsePAM yes/UsePAM no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#TCPKeepAlive yes/TCPKeepAlive no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#VersionAddendum .*$/VersionAddendum none/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#X11Forwarding yes/X11Forwarding no/' \
	/etc/ssh/sshd_config
sed -i '' -e 's/^#PasswordAuthentication no/PasswordAuthentication yes/' \
	/etc/ssh/sshd_config

# Routing options
sysrc -f "$ROUTING_RC_CONF_FILE" icmp_drop_redirect=YES

# Additional TCP/IP options
sysrc -f "$NETOPTIONS_RC_CONF_FILE" ipv6_privacy=YES
sysrc -f "$NETOPTIONS_RC_CONF_FILE" tcp_keepalive=NO
sysrc -f "$NETOPTIONS_RC_CONF_FILE" tcp_drop_synfin=YES

# Additional rc.conf options
sysrc -f "$CLEARTMP_RC_CONF_FILE" clear_tmp_enable=YES
sysrc -f "$SYSLOGD_RC_CONF_FILE" syslogd_flags=-ss

# Change sysctl default values
cat > /etc/sysctl.conf <<- EOF
debug.debugger_on_panic=0
debug.trace_on_panic=1
hw.kbd.keymap_restrict_change=4
kern.ipc.somaxconn=1024
kern.panic_reboot_wait_time=0
kern.randompid=1
net.inet.ip.check_interface=1
net.inet.ip.process_options=0
net.inet.ip.random_id=1
net.inet.ip.redirect=0
net.inet.tcp.blackhole=2
net.inet.tcp.ecn.enable=1
net.inet.tcp.icmp_may_rst=0
net.inet.tcp.mssdflt=1460
net.inet.tcp.nolocaltimewait=1
net.inet.tcp.path_mtu_discovery=0
net.inet.udp.blackhole=1
net.inet6.icmp6.nodeinfo=0
net.inet6.icmp6.rediraccept=0
net.inet6.ip6.redirect=0
security.bsd.hardlink_check_gid=1
security.bsd.hardlink_check_uid=1
security.bsd.see_jail_proc=0
security.bsd.see_other_gids=0
security.bsd.see_other_uids=0
security.bsd.stack_guard_page=1
security.bsd.unprivileged_proc_debug=0
security.bsd.unprivileged_read_msgbuf=0

# Additional hardening settings
net.inet.icmp.icmplim=50
net.inet.icmp.maskrepl=0
net.inet.icmp.drop_redirect=1
net.inet.icmp.bmcastecho=0
net.inet.tcp.icmp_may_rst=0
net.inet.tcp.drop_synfin=1
net.inet.ip.accept_sourceroute=0
net.inet.ip.sourceroute=0
EOF

# Change umask
sed -i '' -e 's/:umask=022:/:umask=027:/g' /etc/login.conf

# Remove toor user
pw userdel toor

# Secure ttys
sed -i '' -e 's/ secure/ insecure/g' /etc/ttys

# Secure newsyslog
sed -i '' -e 's|^/var/log/init.log			644|/var/log/init.log			640|' \
	/etc/newsyslog.conf
sed -i '' -e 's|^/var/log/messages			644|/var/log/messages			640|' \
	/etc/newsyslog.conf
sed -i '' -e 's|^/var/log/devd.log			644|/var/log/devd.log			640|' \
	/etc/newsyslog.conf

# Set shell timeout
echo 'set autologout=15' >> /etc/csh.cshrc
echo "export TMOUT=900" >> /etc/profile

# Set noexec on /tmp and /var/tmp
zfs set exec=off zroot/tmp
zfs set exec=off zroot/var/tmp

# Install IPFW configuration
cat > /etc/ipfw.rules <<EOF
#!/bin/sh

ipfw -q -f flush

cmd="ipfw -q add"
pif="vmx0"

$cmd 00005 allow all from any to any via xl0
$cmd 00010 allow all from any to any via lo0

$cmd 00101 check-state

$cmd 00110 allow tcp from any to me 22 in via $pif setup limit src-addr 2
EOF
chmod +x /etc/ipfw.rules

