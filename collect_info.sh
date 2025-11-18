#!/usr/bin/env bash
# Secure VPS information gathering script for security analysis
# Updated: SAFE_USERS list moved out, extended XRAY search, improved authorized_keys report
# Fixed: Replaced erroneous 'end' with 'done' in services loop

set -euo pipefail  # Strict error handling: exit on error, unset variables, and pipefail

TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="server_audit_${TS}.txt"

# Ensure the script is run as root for full access to system details
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run this script as root (e.g., sudo bash server_audit.sh)."
  exit 1
fi

# Helper function to run a command, add a title, and append output to the audit file
run() {
  local title="$1"
  shift
  {
    echo "=== ${title} ==="
    "$@"
    echo
  } >> "${OUTPUT_FILE}" 2>&1 || true  # Always append, ignore individual command errors
}

echo "=== SERVER INFORMATION COLLECTION ===" > "${OUTPUT_FILE}"
echo "Date: $(date)" >> "${OUTPUT_FILE}"
echo >> "${OUTPUT_FILE}"

# 1. Basic system info: OS release, kernel, uptime
run "1. SYSTEM INFORMATION (uname/os-release/uptime)" bash -c 'uname -a; echo; cat /etc/os-release; echo; echo "Uptime and load:"; uptime'

# 2. Resource usage: memory, disk, top CPU processes
run "2. RESOURCE USAGE — Memory" free -h
run "2. RESOURCE USAGE — Disk" df -h
run "2. RESOURCE USAGE — Top 5 CPU" bash -c 'ps aux --sort=-%cpu | head -6'

# 3. Network interfaces (ip a)
run "3. NETWORK INTERFACES (ip addr show)" ip addr show

# 4. Open ports, with timeout if available (prevents hanging)
if command -v timeout >/dev/null 2>&1; then
  run "4. OPEN PORTS (ss -tulpn)" timeout 5s ss -tulpn
else
  run "4. OPEN PORTS (ss -tulpn)" ss -tulpn
fi

# 5. IPTables rules (INPUT, FORWARD, OUTPUT chains, fail2ban chains)
run "5. IPTABLES — INPUT (first 50 rules)" bash -c 'iptables -L INPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — FORWARD (first 50 rules)" bash -c 'iptables -L FORWARD -n -v --line-numbers | head -50'
run "5. IPTABLES — OUTPUT (first 50 rules)" bash -c 'iptables -L OUTPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — fail2ban chains (overview)" bash -c 'iptables -L -n -v | grep -E "^Chain f2b-|^[0-9]" | head -100'

# 6. Firewalld configuration, only if active
if systemctl is-active --quiet firewalld; then
  run "6. FIREWALLD — list-all" firewall-cmd --list-all
else
  echo "=== 6. FIREWALLD ===" >> "${OUTPUT_FILE}"
  echo "firewalld is not active" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 7. UFW configuration, if available
if command -v ufw >/dev/null 2>&1; then
  run "7. UFW — status verbose" ufw status verbose
else
  echo "=== 7. UFW ===" >> "${OUTPUT_FILE}"
  echo "ufw is not installed" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 8. Fail2ban status and jail breakdown, including recent bans
if command -v fail2ban-client >/dev/null 2>&1; then
  run "8. FAIL2BAN — overall status" fail2ban-client status
  JAILS="$(fail2ban-client status | awk -F: '/Jail list/{print $2}' | tr -d '[:space:]' | tr ',' ' ')"
  for jail in ${JAILS}; do
    run "8. FAIL2BAN — Jail: ${jail}" bash -c "fail2ban-client status ${jail} | grep -E 'Currently banned|Total banned' || true"
  done
  run "8. FAIL2BAN — recent ban events" bash -c 'tail -200 /var/log/fail2ban.log 2>/dev/null | grep -i "ban" | tail -20'
else
  echo "=== 8. FAIL2BAN ===" >> "${OUTPUT_FILE}"
  echo "fail2ban is not installed" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# Function for masking sensitive JSON secrets in XRAY/V2RAY configuration
mask_json() {
  sed -E \
    -e 's/"id": *"[^"]*"/"id": "MASKED_UUID"/g' \
    -e 's/"password": *"[^"]*"/"password": "MASKED_PASS"/g' \
    -e 's/"privateKey": *"[^"]*"/"privateKey": "MASKED_KEY"/g' \
    -e 's/"seed": *"[^"]*"/"seed": "MASKED_SEED"/g' \
    -e 's/"cert": *"[^"]*"/"cert": "MASKED_CERT"/g' \
    -e 's/"user": *"[^"]*"/"user": "MASKED_USER"/g'
}

# XRAY/V2RAY: search standard config locations, mask secrets, dump config if found
XRAY_PATHS=(
  "/usr/local/etc/xray/config.json"
  "/etc/xray/config.json"
  "/usr/local/etc/v2ray/config.json"
  "/etc/v2ray/config.json"
  "/opt/xray/config.json"
  "/opt/v2ray/config.json"
  "/usr/local/xray/config.json"
  "/usr/local/xray/bin/config.json"
  "/usr/local/x-ui/xray/config.json"
  "/usr/local/x-ui/bin/config.json"
)
FOUND_XRAY="no"
for p in "${XRAY_PATHS[@]}"; do
  if [[ -f "${p}" ]]; then
    FOUND_XRAY="yes (${p})"
    {
      echo "=== 9. XRAY/V2RAY CONFIGURATION — found: ${p} (secrets masked) ==="
      mask_json < "${p}"
      echo
    } >> "${OUTPUT_FILE}"
  fi
done
if [[ "${FOUND_XRAY}" == "no" ]]; then
  echo "=== 9. XRAY/V2RAY CONFIGURATION ===" >> "${OUTPUT_FILE}"
  echo "xray/v2ray configuration not found in standard/common paths" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi
run "9. XRAY/X-UI — listening ports (via ss)" bash -c "ss -lntp | grep -E 'xray|x-ui' || true"

# 10. Key services status check (security-related)
SERVICES=(ssh sshd xray v2ray fail2ban ufw iptables firewalld cockpit)
{
  echo "=== 10. KEY SERVICES ==="
  echo "Checking status of security-critical services:"
  for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "${service}" 2>/dev/null; then
      echo "✓ ${service} — ACTIVE"
    else
      echo "• ${service} — not active"
    fi
  done
  echo
} >> "${OUTPUT_FILE}"

# 11. Enabled services (autostart at boot), filtered to relevant services
run "11. ENABLED SERVICES (autostart)" bash -c "systemctl list-unit-files --state=enabled --type=service | grep -E 'ssh|xray|v2ray|fail2ban|firewall|cockpit' || true"

# 12. Active network connections, top 20
run "12. ACTIVE CONNECTIONS (ss -tun, top 20)" bash -c 'ss -tun | head -20'

# 13. SSHD configuration without comments (for audit)
run "13. SSHD_CONFIG (comments removed)" bash -c 'grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config || true'

# 14. SSH logins: last accepted, last failed
run "14. SSH — Accepted (journalctl tail 20)" bash -c 'journalctl _COMM=sshd --no-pager 2>/dev/null | grep "Accepted" | tail -20'
run "14. SSH — Failed attempts (lastb -20)" bash -c 'lastb -20 2>/dev/null || true'

# 15. SUDO privilege groups and files
run "15. SUDO groups (wheel/sudo)" bash -c 'getent group wheel sudo 2>/dev/null || true'
run "15. SUDOERS files (/etc/sudoers.d)" bash -c 'ls -la /etc/sudoers.d/ 2>/dev/null || true'

# 16. authorized_keys — extended report on root authentication keys
if [[ -f /root/.ssh/authorized_keys ]]; then
  {
    echo "=== 16. SSH AUTHORIZED_KEYS (root) ==="
    echo "File metadata:"
    stat -c 'Path: %n | Size: %s | Owner: %U:%G | Mode: %a | MTime: %y' /root/.ssh/authorized_keys 2>/dev/null || ls -l /root/.ssh/authorized_keys
    echo "Number of keys:"
    wc -l /root/.ssh/authorized_keys
    echo "Fingerprints:"
    ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null || true
    echo "First 16 characters of each key (comments stripped):"
    awk 'NF>=2 {print substr($2,1,16)}' /root/.ssh/authorized_keys 2>/dev/null || true
    echo
  } >> "${OUTPUT_FILE}"
else
  echo "=== 16. SSH AUTHORIZED_KEYS (root) ===" >> "${OUTPUT_FILE}"
  echo "authorized_keys file for root not found" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 17. Root crontab and /etc/cron.d jobs
run "17. Root crontab" bash -c 'crontab -l 2>/dev/null || true'
run "17. System cron.d" bash -c 'ls -la /etc/cron.d/ 2>/dev/null || true'

# 18. OS package updates (APT or YUM — security & other updates)
if command -v apt >/dev/null 2>&1; then
  run "18. APT — available updates" bash -c 'apt update -o DPkg::Lock::Timeout=30 >/dev/null 2>&1 || true; apt list --upgradable 2>/dev/null | sed "1d"'
  run "18. APT — security (by name)" bash -c 'apt list --upgradable 2>/dev/null | grep -i security || true'
elif command -v yum >/dev/null 2>&1; then
  run "18. YUM — available updates" bash -c 'yum check-update 2>/dev/null || true'
  run "18. YUM — security" bash -c 'yum updateinfo list security 2>/dev/null || true'
else
  echo "=== 18. SYSTEM UPDATES ===" >> "${OUTPUT_FILE}"
  echo "Package manager (apt/yum) not found" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 19. List of SAFE USERS taken out of regex, search for suspicious processes
# Only show processes whose user does NOT match the SAFE_USERS_REGEX
SAFE_USERS_REGEX='^(root|systemd|dbus|messagebus|chrony|polkitd|rpc|sshd|fail2ban|www-data|nginx|postgres|mysql|grafana|prometheus|systemd-resolve|systemd-timesync|systemd-network|syslog|smart)$'
run "19. SUSPICIOUS PROCESSES (excluding SAFE users)" bash -c "ps aux | awk '\$1 !~ /${SAFE_USERS_REGEX}/ {print}' | head -30"

# 20. SSH PermitRootLogin settings (security check)
run "20. SSH — PermitRootLogin" bash -c 'grep -E "^PermitRootLogin" /etc/ssh/sshd_config || true'

# 21. SUDO logs (auth.log tail, recent sudo events)
run "21. SUDO LOGS (auth.log tail)" bash -c 'tail -200 /var/log/auth.log 2>/dev/null | grep sudo | tail -20 || true'

# 22. Kernel and Journal logs (critical messages)
run "22. DMESG tail-20" bash -c 'dmesg | tail -20 || true'
run "22. JOURNALCTL — errors (prio=3) tail-20" bash -c 'journalctl -p 3 -xb --no-pager 2>/dev/null | tail -20 || true'

# 23. /etc/passwd: login names and shells
run "23. /etc/passwd (login and shell)" bash -c 'awk -F: '\''{ print $1": "$7 }'\'' /etc/passwd'

# 24. SUID/SGID files (security-sensitive), top 20
run "24. SUID/SGID files (top 20)" bash -c 'find / -xdev -perm /6000 -type f 2>/dev/null | head -20'

# 25. Listening processes (ss summary), top 100 lines
run "25. LISTENING PROCESSES (ss brief)" bash -c 'ss -tulnp | awk '\''{print $1, $5, $6, $7}'\'' | head -100'

# 26. Autostart scripts: /etc/rc.local and /etc/init.d
run "26. Autostart — /etc/rc.local" bash -c 'ls -la /etc/rc.local 2>/dev/null || true'
run "26. Autostart — /etc/init.d (top 20)" bash -c 'ls -la /etc/init.d/ 2>/dev/null | head -20 || true'

# 27. Kernel version and top modules
run "27. Kernel (uname -r)" uname -r
run "27. Kernel modules (lsmod top 20)" bash -c 'lsmod | head -20 || true'

{
  echo "=== AUDIT COMPLETE ==="
  echo "File saved: ${OUTPUT_FILE}"
} >> "${OUTPUT_FILE}"

echo "File saved: ${OUTPUT_FILE}"
echo "To send this report, you can archive it: tar -czf ${OUTPUT_FILE%.txt}.tar.gz ${OUTPUT_FILE}"
