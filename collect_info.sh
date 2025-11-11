# filename: server_audit.sh
#!/usr/bin/env bash
# Безопасный сбор информации о VPS для анализа безопасности
# Обновлено: вынесен список SAFE_USERS, расширен XRAY-поиск, улучшен отчёт authorized_keys

set -euo pipefail

TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="server_audit_${TS}.txt"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Пожалуйста, запускайте этот скрипт от root (например: sudo bash server_audit.sh)."
  exit 1
fi

run() {
  local title="$1"
  shift
  {
    echo "=== ${title} ==="
    "$@"
    echo
  } >> "${OUTPUT_FILE}" 2>&1 || true
}

echo "=== СБОР ИНФОРМАЦИИ О СЕРВЕРЕ ===" > "${OUTPUT_FILE}"
echo "Дата: $(date)" >> "${OUTPUT_FILE}"
echo >> "${OUTPUT_FILE}"

run "1. ИНФОРМАЦИЯ О СИСТЕМЕ (uname/os-release/uptime)" bash -c 'uname -a; echo; cat /etc/os-release; echo; echo "Uptime и загрузка:"; uptime'

run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — память" free -h
run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — диск" df -h
run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — CPU топ 5" bash -c 'ps aux --sort=-%cpu | head -6'

run "3. СЕТЕВЫЕ ИНТЕРФЕЙСЫ (ip addr show)" ip addr show

if command -v timeout >/dev/null 2>&1; then
  run "4. ОТКРЫТЫЕ ПОРТЫ (ss -tulpn)" timeout 5s ss -tulpn
else
  run "4. ОТКРЫТЫЕ ПОРТЫ (ss -tulpn)" ss -tulpn
fi

run "5. IPTABLES — INPUT (первые 50 правил)" bash -c 'iptables -L INPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — FORWARD (первые 50 правил)" bash -c 'iptables -L FORWARD -n -v --line-numbers | head -50'
run "5. IPTABLES — OUTPUT (первые 50 правил)" bash -c 'iptables -L OUTPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — fail2ban цепочки (обзор)" bash -c 'iptables -L -n -v | grep -E "^Chain f2b-|^[0-9]" | head -100'

if systemctl is-active --quiet firewalld; then
  run "6. FIREWALLD — list-all" firewall-cmd --list-all
else
  echo "=== 6. FIREWALLD ===" >> "${OUTPUT_FILE}"
  echo "firewalld не активен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

if command -v ufw >/dev/null 2>&1; then
  run "7. UFW — status verbose" ufw status verbose
else
  echo "=== 7. UFW ===" >> "${OUTPUT_FILE}"
  echo "ufw не установлен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  run "8. FAIL2BAN — общий статус" fail2ban-client status
  JAILS="$(fail2ban-client status | awk -F: '/Jail list/{print $2}' | tr -d '[:space:]' | tr ',' ' ')"
  for jail in ${JAILS}; do
    run "8. FAIL2BAN — Jail: ${jail}" bash -c "fail2ban-client status ${jail} | grep -E 'Currently banned|Total banned' || true"
  done
  run "8. FAIL2BAN — последние события (ban)" bash -c 'tail -200 /var/log/fail2ban.log 2>/dev/null | grep -i "ban" | tail -20'
else
  echo "=== 8. FAIL2BAN ===" >> "${OUTPUT_FILE}"
  echo "fail2ban не установлен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

mask_json() {
  sed -E \
    -e 's/"id": *"[^"]*"/"id": "MASKED_UUID"/g' \
    -e 's/"password": *"[^"]*"/"password": "MASKED_PASS"/g' \
    -e 's/"privateKey": *"[^"]*"/"privateKey": "MASKED_KEY"/g' \
    -e 's/"seed": *"[^"]*"/"seed": "MASKED_SEED"/g' \
    -e 's/"cert": *"[^"]*"/"cert": "MASKED_CERT"/g' \
    -e 's/"user": *"[^"]*"/"user": "MASKED_USER"/g'
}

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
FOUND_XRAY="нет"
for p in "${XRAY_PATHS[@]}"; do
  if [[ -f "${p}" ]]; then
    FOUND_XRAY="да (${p})"
    {
      echo "=== 9. XRAY/V2RAY КОНФИГУРАЦИЯ — найден: ${p} (секреты маскированы) ==="
      mask_json < "${p}"
      echo
    } >> "${OUTPUT_FILE}"
  fi
done
if [[ "${FOUND_XRAY}" == "нет" ]]; then
  echo "=== 9. XRAY/V2RAY КОНФИГУРАЦИЯ ===" >> "${OUTPUT_FILE}"
  echo "xray/v2ray конфигурация не найдена в стандартных/частых путях" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi
run "9. XRAY/X-UI — слушающие порты (по ss)" bash -c "ss -lntp | grep -E 'xray|x-ui' || true"

SERVICES=(ssh sshd xray v2ray fail2ban ufw iptables firewalld cockpit)
{
  echo "=== 10. КЛЮЧЕВЫЕ СЕРВИСЫ ==="
  echo "Проверка важных для безопасности сервисов:"
  for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "${service}" 2>/dev/null; then
      echo "✓ ${service} — АКТИВЕН"
    else
      echo "• ${service} — не активен"
    fi
  end
  echo
} >> "${OUTPUT_FILE}"

run "11. АВТОЗАПУСК СЕРВИСОВ (enabled)" bash -c "systemctl list-unit-files --state=enabled --type=service | grep -E 'ssh|xray|v2ray|fail2ban|firewall|cockpit' || true"

run "12. АКТИВНЫЕ СОЕДИНЕНИЯ (ss -tun, топ-20)" bash -c 'ss -tun | head -20'

run "13. SSHD_CONFIG (очищено от комментариев)" bash -c 'grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config || true'

run "14. SSH — Accepted (journalctl хвост 20)" bash -c 'journalctl _COMM=sshd --no-pager 2>/dev/null | grep "Accepted" | tail -20'
run "14. SSH — Неудачные попытки (lastb -20)" bash -c 'lastb -20 2>/dev/null || true'

run "15. SUDO группы (wheel/sudo)" bash -c 'getent group wheel sudo 2>/dev/null || true'
run "15. SUDOERS файлы (/etc/sudoers.d)" bash -c 'ls -la /etc/sudoers.d/ 2>/dev/null || true'

# 16. authorized_keys — расширенный отчёт
if [[ -f /root/.ssh/authorized_keys ]]; then
  {
    echo "=== 16. SSH AUTHORIZED_KEYS (root) ==="
    echo "Метаданные файла:"
    stat -c 'Path: %n | Size: %s | Owner: %U:%G | Mode: %a | MTime: %y' /root/.ssh/authorized_keys 2>/dev/null || ls -l /root/.ssh/authorized_keys
    echo "Количество ключей:"
    wc -l /root/.ssh/authorized_keys
    echo "Fingerprints:"
    ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null || true
    echo "Первые 16 символов каждого ключа (без комментариев):"
    awk 'NF>=2 {print substr($2,1,16)}' /root/.ssh/authorized_keys 2>/dev/null || true
    echo
  } >> "${OUTPUT_FILE}"
else
  echo "=== 16. SSH AUTHORIZED_KEYS (root) ===" >> "${OUTPUT_FILE}"
  echo "Файл authorized_keys для root не найден" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

run "17. Root crontab" bash -c 'crontab -l 2>/dev/null || true'
run "17. Системные cron.d" bash -c 'ls -la /etc/cron.d/ 2>/dev/null || true'

if command -v apt >/dev/null 2>&1; then
  run "18. APT — доступные обновления" bash -c 'apt update -o DPkg::Lock::Timeout=30 >/dev/null 2>&1 || true; apt list --upgradable 2>/dev/null | sed "1d"'
  run "18. APT — security (по названию)" bash -c 'apt list --upgradable 2>/dev/null | grep -i security || true'
elif command -v yum >/dev/null 2>&1; then
  run "18. YUM — доступные обновления" bash -c 'yum check-update 2>/dev/null || true'
  run "18. YUM — security" bash -c 'yum updateinfo list security 2>/dev/null || true'
else
  echo "=== 18. ОБНОВЛЕНИЯ СИСТЕМЫ ===" >> "${OUTPUT_FILE}"
  echo "Менеджер пакетов (apt/yum) не найден" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 19. SAFE_USERS вынесены в переменную
SAFE_USERS_REGEX='^(root|systemd|dbus|messagebus|chrony|polkitd|rpc|sshd|fail2ban|www-data|nginx|postgres|mysql|grafana|prometheus|systemd-resolve|systemd-timesync|systemd-network|syslog|smart)$'
run "19. ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ (исключая SAFE-юзеров)" bash -c "ps aux | awk '\$1 !~ /${SAFE_USERS_REGEX}/ {print}' | head -30"

run "20. SSH — PermitRootLogin" bash -c 'grep -E "^PermitRootLogin" /etc/ssh/sshd_config || true'

run "21. ЛОГИ SUDO (auth.log хвост)" bash -c 'tail -200 /var/log/auth.log 2>/dev/null | grep sudo | tail -20 || true'

run "22. DMESG хвост-20" bash -c 'dmesg | tail -20 || true'
run "22. JOURNALCTL — ошибки (prio=3) хвост-20" bash -c 'journalctl -p 3 -xb --no-pager 2>/dev/null | tail -20 || true'

run "23. /etc/passwd (логин и shell)" bash -c 'awk -F: '\''{ print $1": "$7 }'\'' /etc/passwd'

run "24. SUID/SGID файлы (топ-20)" bash -c 'find / -xdev -perm /6000 -type f 2>/dev/null | head -20'

run "25. СЛУШАЮЩИЕ ПРОЦЕССЫ (ss кратко)" bash -c 'ss -tulnp | awk '\''{print $1, $5, $6, $7}'\'' | head -100'

run "26. Автозапуск — /etc/rc.local" bash -c 'ls -la /etc/rc.local 2>/dev/null || true'
run "26. Автозапуск — /etc/init.d (топ-20)" bash -c 'ls -la /etc/init.d/ 2>/dev/null | head -20 || true'

run "27. Ядро (uname -r)" uname -r
run "27. Модули ядра (lsmod топ-20)" bash -c 'lsmod | head -20 || true'

{
  echo "=== СБОР ЗАВЕРШЁН ==="
  echo "Файл сохранён: ${OUTPUT_FILE}"
} >> "${OUTPUT_FILE}"

echo "Файл сохранён: ${OUTPUT_FILE}"
echo "Чтобы отправить отчёт, можно упаковать: tar -czf ${OUTPUT_FILE%.txt}.tar.gz ${OUTPUT_FILE}"
