#!/usr/bin/env bash
# Secure VPS information gathering script for security analysis
# Updated:
# - SAFE_USERS regex can be overridden via env
# - Extended XRAY search and masking
# - Improved authorized_keys report
# - Added timeouts where possible
# - Added nftables section
# - Extended SSH hardening checks
# - Fixed numbering of sections
# - Added JSON summary output for automated parsing
# - Fixed awk parsing for fail2ban banned count
# - Fixed unbound variable issue with $1 in suspicious processes block
# - Fixed quoting in listening processes block

set -euo pipefail  # Strict error handling: exit on error, unset variables, and pipefail

TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="server_audit_${TS}.txt"
JSON_FILE="server_audit_${TS}.json"

# Ensure the script is run as root for full access to system details
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run this script as root (e.g., sudo bash server_audit.sh)."
  exit 1
fi

# Helper to run a command with optional timeout
run_cmd_with_timeout() {
  local timeout_sec="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}" "$@"
  else
    "$@"
  fi
}

# Helper function to run a command, add a title, and append output to the audit file
run() {
  local title="$1"
  shift
  {
    echo "=== ${title} ==="
    "$@"
    echo
  } >> "${OUTPUT_FILE}" 2>&1 || true
}

# --- JSON helper variables ---
JSON_TIMESTAMP=""
JSON_HOSTNAME=""
JSON_SSH_PERMIT_ROOT=""
JSON_SSH_PASSWORD_AUTH=""
JSON_SSH_PORT=""
JSON_FIREWALL_IPTABLES="false"
JSON_FIREWALL_NFTABLES="false"
JSON_FIREWALL_UFW_ACTIVE="false"
JSON_FIREWALL_FIREWALLD_ACTIVE="false"
JSON_FAIL2BAN_INSTALLED="false"
JSON_FAIL2BAN_JAILS="[]"
JSON_FAIL2BAN_BANNED_TOTAL=0

# Get basic metadata for JSON
JSON_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
JSON_HOSTNAME="$(hostname 2>/dev/null || echo "unknown")"

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
run "4. OPEN PORTS (ss -tulpn)" bash -c 'command -v timeout >/dev/null 2>&1 && timeout 5s ss -tulpn || ss -tulpn'

# 5. IPTables rules (INPUT, FORWARD, OUTPUT chains, fail2ban chains)
if command -v iptables >/dev/null 2>&1; then
  JSON_FIREWALL_IPTABLES="true"
fi
run "5. IPTABLES — INPUT (first 50 rules)" bash -c 'iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -50 || echo "iptables not available"'
run "5. IPTABLES — FORWARD (first 50 rules)" bash -c 'iptables -L FORWARD -n -v --line-numbers 2>/dev/null | head -50 || echo "iptables not available"'
run "5. IPTABLES — OUTPUT (first 50 rules)" bash -c 'iptables -L OUTPUT -n -v --line-numbers 2>/dev/null | head -50 || echo "iptables not available"'
run "5. IPTABLES — fail2ban chains (overview)" bash -c 'iptables -L -n -v 2>/dev/null | grep -E "^Chain f2b-|^[0-9]" | head -100 || echo "iptables not available or no fail2ban chains"'

# 6. nftables configuration, if available
if command -v nft >/dev/null 2>&1; then
  JSON_FIREWALL_NFTABLES="true"
  run "6. NFTABLES — ruleset" bash -c 'nft list ruleset 2>/dev/null || echo "nftables installed but failed to list ruleset"'
else
  {
    echo "=== 6. NFTABLES ==="
    echo "nftables is not installed or not in PATH"
    echo
  } >> "${OUTPUT_FILE}"
fi

# 7. Firewalld configuration, only if active
if systemctl is-active --quiet firewalld; then
  JSON_FIREWALL_FIREWALLD_ACTIVE="true"
  run "7. FIREWALLD — list-all" firewall-cmd --list-all
else
  {
    echo "=== 7. FIREWALLD ==="
    echo "firewalld is not active."
    echo "Note: server may rely on iptables/nftables directly or have no L3 firewall."
    echo
  } >> "${OUTPUT_FILE}"
fi

# 8. UFW configuration, if available
if command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -qi "Status: active"; then
    JSON_FIREWALL_UFW_ACTIVE="true"
  fi
  run "8. UFW — status verbose" ufw status verbose
else
  {
    echo "=== 8. UFW ==="
    echo "ufw is not installed."
    echo "Note: firewall may be managed via firewalld/iptables/nftables or not configured."
    echo
  } >> "${OUTPUT_FILE}"
fi

# 9. Fail2ban status and jail breakdown, including recent bans
if command -v fail2ban-client >/dev/null 2>&1; then
  JSON_FAIL2BAN_INSTALLED="true"
  F2B_STATUS="$(fail2ban-client status 2>/dev/null || true)"
  run "9. FAIL2BAN — overall status" bash -c 'fail2ban-client status'
  JAILS="$(echo "${F2B_STATUS}" | awk -F: '/Jail list/{print $2}' | tr -d "[:space:]" | tr "," " ")"

  if [[ -n "${JAILS}" ]]; then
    jlist=""
    for jail in ${JAILS}; do
      JSTAT="$(fail2ban-client status "${jail}" 2>/dev/null || true)"
      BANNED="$(echo "${JSTAT}" | awk -F':' '/Currently banned/ {print $2}' | tr -d '[:space:]')"
      if [[ -n "${BANNED}" ]]; then
        JSON_FAIL2BAN_BANNED_TOTAL=$(( JSON_FAIL2BAN_BANNED_TOTAL + BANNED ))
      fi
      jlist="${jlist}\"${jail}\","
      run "9. FAIL2BAN — Jail: ${jail}" bash -c "fail2ban-client status ${jail} | grep -E 'Currently banned|Total banned' || true"
    done
    JSON_FAIL2BAN_JAILS="[$(echo "${jlist}" | sed 's/,$//')]"
  fi

  run "9. FAIL2BAN — recent ban events" bash -c 'tail -200 /var/log/fail2ban.log 2>/dev/null | grep -i "ban" | tail -20'
else
  {
    echo "=== 9. FAIL2BAN ==="
    echo "fail2ban is not installed"
    echo
  } >> "${OUTPUT_FILE}"
fi

# Function for masking sensitive JSON secrets in XRAY/V2RAY configuration
mask_json() {
  sed -E \
    -e 's/"id"[[:space:]]*:[[:space:]]*"[^"]*"/"id": "MASKED_UUID"/g' \
    -e 's/"password"[[:space:]]*:[[:space:]]*"[^"]*"/"password": "MASKED_PASS"/g' \
    -e 's/"privateKey"[[:space:]]*:[[:space:]]*"[^"]*"/"privateKey": "MASKED_KEY"/g' \
    -e 's/"seed"[[:space:]]*:[[:space:]]*"[^"]*"/"seed": "MASKED_SEED"/g' \
    -e 's/"cert"[[:space:]]*:[[:space:]]*"[^"]*"/"cert": "MASKED_CERT"/g' \
    -e 's/"user"[[:space:]]*:[[:space:]]*"[^"]*"/"user": "MASKED_USER"/g'
}

# 10. XRAY/V2RAY: search standard config locations, mask secrets, dump config if found
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
      echo "=== 10. XRAY/V2RAY CONFIGURATION — found: ${p} (secrets masked) ==="
      mask_json < "${p}"
      echo
    } >> "${OUTPUT_FILE}"
  fi
done
if [[ "${FOUND_XRAY}" == "no" ]]; then
  {
    echo "=== 10. XRAY/V2RAY CONFIGURATION ==="
    echo "xray/v2ray configuration not found in standard/common paths"
    echo
  } >> "${OUTPUT_FILE}"
fi

# 11. XRAY/X-UI listening ports
run "11. XRAY/X-UI — listening ports (via ss)" bash -c "command -v timeout >/dev/null 2>&1 && timeout 5s ss -lntp || ss -lntp | grep -E 'xray|x-ui' || true"

# 12. Key services status check (security-related)
SERVICES=(ssh sshd xray v2ray fail2ban ufw iptables firewalld cockpit)
{
  echo "=== 12. KEY SERVICES ==="
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

# 13. Enabled services (autostart at boot), filtered to relevant services
run "13. ENABLED SERVICES (autostart)" bash -c "systemctl list-unit-files --state=enabled --type=service | grep -E 'ssh|xray|v2ray|fail2ban|firewall|cockpit' || true"

# 14. Active network connections, top 20
run "14. ACTIVE CONNECTIONS (ss -tun, top 20)" bash -c 'command -v timeout >/dev/null 2>&1 && timeout 5s ss -tun || ss -tun | head -20'

# 15. SSHD configuration without comments (for audit)
run "15. SSHD_CONFIG (comments removed)" bash -c 'grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config 2>/dev/null || echo "sshd_config not found or not readable"'

# 16. SSH hardening checks (PermitRootLogin, PasswordAuthentication, etc.) + JSON extraction
SSH_CFG="/etc/ssh/sshd_config"
if [[ -f "${SSH_CFG}" ]]; then
  JSON_SSH_PERMIT_ROOT="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*#/ {next} /PermitRootLogin/ {val=$2} END{print val}' "${SSH_CFG}" 2>/dev/null || true)"
  JSON_SSH_PASSWORD_AUTH="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*#/ {next} /PasswordAuthentication/ {val=$2} END{print val}' "${SSH_CFG}" 2>/dev/null || true)"
  JSON_SSH_PORT="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*#/ {next} /^Port[[:space:]]+/ {val=$2} END{print val}' "${SSH_CFG}" 2>/dev/null || true)"
fi

run "16. SSH HARDENING — key options" bash -c '
  CFG=/etc/ssh/sshd_config
  if [[ ! -f "$CFG" ]]; then
    echo "sshd_config not found"
    exit 0
  fi
  echo "Effective SSH security-related options (last occurrence wins):"
  awk "
    /^[[:space:]]*#/ {next}
    NF==0 {next}
    {print toupper(\$1), \$2}
  " "$CFG" | awk "
    BEGIN{IGNORECASE=1}
    \$1 ~ /PERMITROOTLOGIN|PASSWORDAUTHENTICATION|PUBKEYAUTHENTICATION|MAXAUTHTRIES|ALLOWUSERS|ALLOWGROUPS|DENYUSERS|DENYGROUPS/ {
      key=\$1
      val=\"\"
      for (i=2; i<=NF; i++) {val=val \$i\" \"}
      gsub(/[[:space:]]+$/, \"\", val)
      map[key]=val
    }
    END{
      for (k in map) {
        printf \"%-24s %s\n\", k\":\", map[k]
      }
    }
  "
'

# 17. SSH logins: last accepted, last failed
run "17. SSH — Accepted (journalctl tail 20)" bash -c 'journalctl _COMM=sshd --no-pager 2>/dev/null | grep "Accepted" | tail -20'
run "17. SSH — Failed attempts (lastb -20)" bash -c 'lastb -20 2>/dev/null || true'

# 18. SUDO privilege groups and files
run "18. SUDO groups (wheel/sudo)" bash -c 'getent group wheel sudo 2>/dev/null || true'
run "18. SUDOERS files (/etc/sudoers.d)" bash -c 'ls -la /etc/sudoers.d/ 2>/dev/null || true'

# 19. authorized_keys — extended report on root authentication keys
if [[ -f /root/.ssh/authorized_keys ]]; then
  {
    echo "=== 19. SSH AUTHORIZED_KEYS (root) ==="
    echo "File meta"
    stat -c "Path: %n | Size: %s | Owner: %U:%G | Mode: %a | MTime: %y" /root/.ssh/authorized_keys 2>/dev/null || ls -l /root/.ssh/authorized_keys
    echo "Number of keys:"
    wc -l /root/.ssh/authorized_keys
    echo "Fingerprints:"
    ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null || true
    echo "First 16 characters of each key (comments stripped):"
    awk "NF>=2 {print substr(\$2,1,16)}" /root/.ssh/authorized_keys 2>/dev/null || true
    echo
  } >> "${OUTPUT_FILE}"
else
  {
    echo "=== 19. SSH AUTHORIZED_KEYS (root) ==="
    echo "authorized_keys file for root not found"
    echo
  } >> "${OUTPUT_FILE}"
fi

# 20. Root crontab and /etc/cron.d jobs
run "20. Root crontab" bash -c 'crontab -l 2>/dev/null || true'
run "20. System cron.d" bash -c 'ls -la /etc/cron.d/ 2>/dev/null || true'

# 21. OS package updates (APT or YUM — security & other updates)
if command -v apt >/dev/null 2>&1; then
  run "21. APT — available updates" bash -c 'apt update -o DPkg::Lock::Timeout=30 >/dev/null 2>&1 || true; apt list --upgradable 2>/dev/null | sed "1d"'
  run "21. APT — security (by name)" bash -c 'apt list --upgradable 2>/dev/null | grep -i security || true'
elif command -v yum >/dev/null 2>&1; then
  run "21. YUM — available updates" bash -c 'yum check-update 2>/dev/null || true'
  run "21. YUM — security" bash -c 'yum updateinfo list security 2>/dev/null || true'
else
  {
    echo "=== 21. SYSTEM UPDATES ==="
    echo "Package manager (apt/yum) not found"
    echo
  } >> "${OUTPUT_FILE}"
fi

# 22. List of SAFE USERS taken out of regex, search for suspicious processes
DEFAULT_SAFE_USERS_REGEX='^(root|systemd|dbus|messagebus|chrony|polkitd|rpc|sshd|fail2ban|www-data|nginx|postgres|mysql|grafana|prometheus|systemd-resolve|systemd-timesync|systemd-network|syslog|smart)$'
SAFE_USERS_REGEX="${SAFE_USERS_REGEX:-$DEFAULT_SAFE_USERS_REGEX}"
run "22. SUSPICIOUS PROCESSES (excluding SAFE users)" bash -c "
  ps aux | awk '
    !(\$1 ~ /${SAFE_USERS_REGEX}/) {print}
  ' | head -30
"

# 23. SSH PermitRootLogin settings (security check)
run "23. SSH — PermitRootLogin" bash -c 'grep -E "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "PermitRootLogin not explicitly set (default may apply)"'

# 24. SUDO logs (auth.log tail, recent sudo events)
run "24. SUDO LOGS (auth.log tail)" bash -c 'tail -200 /var/log/auth.log 2>/dev/null | grep sudo | tail -20 || true'

# 25. Kernel and Journal logs (critical messages)
run "25. DMESG tail-20" bash -c 'command -v timeout >/dev/null 2>&1 && timeout 5s dmesg || dmesg | tail -20 || true'
run "25. JOURNALCTL — errors (prio=3) tail-20" bash -c 'journalctl -p 3 -xb --no-pager 2>/dev/null | tail -20 || true'

# 26. /etc/passwd: login names and shells
run "26. /etc/passwd (login and shell)" bash -c "awk -F: '{ print \$1\": \"\$7 }' /etc/passwd"

# 27. SUID/SGID files (security-sensitive), top 20
run "27. SUID/SGID files (top 20)" bash -c 'command -v timeout >/dev/null 2>&1 && timeout 10s find / -xdev -perm /6000 -type f 2>/dev/null || find / -xdev -perm /6000 -type f 2>/dev/null | head -20'

# 28. Listening processes (ss summary), top 100 lines
run "28. LISTENING PROCESSES (ss brief)" bash -c '
  if command -v timeout >/dev/null 2>&1; then
    timeout 5s ss -tulnp
  else
    ss -tulnp
  fi | awk "{print \$1, \$5, \$6, \$7}" | head -100
'

# 29. Autostart scripts: /etc/rc.local and /etc/init.d
run "29. Autostart — /etc/rc.local" bash -c 'ls -la /etc/rc.local 2>/dev/null || true'
run "29. Autostart — /etc/init.d (top 20)" bash -c 'ls -la /etc/init.d/ 2>/dev/null | head -20 || true'

# 30. Kernel version and top modules
run "30. Kernel (uname -r)" uname -r
run "30. Kernel modules (lsmod top 20)" bash -c 'lsmod | head -20 || true'

# --- Write JSON summary file ---
{
  echo "{"
  echo "  \"timestamp\": \"${JSON_TIMESTAMP}\","
  echo "  \"hostname\": \"${JSON_HOSTNAME}\","
  echo "  \"ssh\": {"
  echo "    \"permit_root_login\": \"${JSON_SSH_PERMIT_ROOT}\","
  echo "    \"password_authentication\": \"${JSON_SSH_PASSWORD_AUTH}\","
  echo "    \"port\": \"${JSON_SSH_PORT}\""
  echo "  },"
  echo "  \"firewall\": {"
  echo "    \"iptables_present\": ${JSON_FIREWALL_IPTABLES},"
  echo "    \"nftables_present\": ${JSON_FIREWALL_NFTABLES},"
  echo "    \"ufw_active\": ${JSON_FIREWALL_UFW_ACTIVE},"
  echo "    \"firewalld_active\": ${JSON_FIREWALL_FIREWALLD_ACTIVE}"
  echo "  },"
  echo "  \"fail2ban\": {"
  echo "    \"installed\": ${JSON_FAIL2BAN_INSTALLED},"
  echo "    \"jails\": ${JSON_FAIL2BAN_JAILS},"
  echo "    \"currently_banned_total\": ${JSON_FAIL2BAN_BANNED_TOTAL}"
  echo "  }"
  echo "}"
} > "${JSON_FILE}"

{
  echo "=== AUDIT COMPLETE ==="
  echo "File saved: ${OUTPUT_FILE}"
  echo "JSON summary: ${JSON_FILE}"
} >> "${OUTPUT_FILE}"

echo "File saved: ${OUTPUT_FILE}"
echo "JSON summary: ${JSON_FILE}"
if command -v tar >/dev/null 2>&1; then
  echo "You can archive them with: tar -czf ${OUTPUT_FILE%.txt}.tar.gz ${OUTPUT_FILE} ${JSON_FILE}"
else
  echo "To send this report, install tar and run: tar -czf ${OUTPUT_FILE%.txt}.tar.gz ${OUTPUT_FILE} ${JSON_FILE}"
fi
