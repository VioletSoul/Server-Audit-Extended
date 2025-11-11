# filename: server_audit.sh
#!/usr/bin/env bash
# Скрипт безопасного сбора информации о VPS для анализа безопасности
# Читает системную информацию, НЕ меняет конфигурации и НЕ останавливает сервисы.
# Маскирует чувствительные поля в конфиге XRAY/V2RAY.

set -euo pipefail

# Настройки вывода
TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="server_audit_${TS}.txt"

# Требуем root для равномерного доступа к логам/конфигам, но не используем 'sudo' внутри
if [[ "${EUID}" -ne 0 ]]; then
  echo "Пожалуйста, запускайте этот скрипт от root (например: sudo bash server_audit.sh)."
  exit 1
fi

# Функция безопасного выполнения команды с заголовком
run() {
  local title="$1"
  shift
  {
    echo "=== ${title} ==="
    "$@"
    echo
  } >> "${OUTPUT_FILE}" 2>&1 || true
}

# Начало файла
echo "=== СБОР ИНФОРМАЦИИ О СЕРВЕРЕ ===" > "${OUTPUT_FILE}"
echo "Дата: $(date)" >> "${OUTPUT_FILE}"
echo >> "${OUTPUT_FILE}"

# 1. Информация о системе
run "1. ИНФОРМАЦИЯ О СИСТЕМЕ (uname/os-release/uptime)" bash -c 'uname -a; echo; cat /etc/os-release; echo; echo "Uptime и загрузка:"; uptime'

# 2. Использование ресурсов
run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — память" free -h
run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — диск" df -h
run "2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ — CPU топ 5" bash -c 'ps aux --sort=-%cpu | head -6'

# 3. Сетевые интерфейсы
run "3. СЕТЕВЫЕ ИНТЕРФЕЙСЫ (ip addr show)" ip addr show

# 4. Открытые порты
# ss может зависать при больших таблицах — ограничим таймаут через timeout, если доступен
if command -v timeout >/dev/null 2>&1; then
  run "4. ОТКРЫТЫЕ ПОРТЫ (ss -tulpn)" timeout 5s ss -tulpn
else
  run "4. ОТКРЫТЫЕ ПОРТЫ (ss -tulpn)" ss -tulpn
fi

# 5. Правила firewall (iptables)
# Не используем sudo внутри; показываем первые 50 строк для читабельности
run "5. IPTABLES — INPUT (первые 50 правил)" bash -c 'iptables -L INPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — FORWARD (первые 50 правил)" bash -c 'iptables -L FORWARD -n -v --line-numbers | head -50'
run "5. IPTABLES — OUTPUT (первые 50 правил)" bash -c 'iptables -L OUTPUT -n -v --line-numbers | head -50'
run "5. IPTABLES — fail2ban цепочки (обзор)" bash -c 'iptables -L -n -v | grep -E "^Chain f2b-|^[0-9]" | head -100'

# 6. Firewalld (если активен)
if systemctl is-active --quiet firewalld; then
  run "6. FIREWALLD — list-all" firewall-cmd --list-all
else
  echo "=== 6. FIREWALLD ===" >> "${OUTPUT_FILE}"
  echo "firewalld не активен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 7. UFW (если установлен)
if command -v ufw >/dev/null 2>&1; then
  run "7. UFW — status verbose" ufw status verbose
else
  echo "=== 7. UFW ===" >> "${OUTPUT_FILE}"
  echo "ufw не установлен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 8. Fail2ban статус
if command -v fail2ban-client >/dev/null 2>&1; then
  run "8. FAIL2BAN — общий статус" fail2ban-client status
  # Список jail-ов
  JAILS="$(fail2ban-client status | awk -F: '/Jail list/{print $2}' | tr -d '[:space:]' | tr ',' ' ')"
  for jail in ${JAILS}; do
    run "8. FAIL2BAN — Jail: ${jail}" bash -c "fail2ban-client status ${jail} | grep -E 'Currently banned|Total banned' || true"
  done
  run "8. FAIL2BAN — последние события (ban) из /var/log/fail2ban.log" bash -c 'tail -200 /var/log/fail2ban.log 2>/dev/null | grep -i "ban" | tail -20'
else
  echo "=== 8. FAIL2BAN ===" >> "${OUTPUT_FILE}"
  echo "fail2ban не установлен" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 9. XRAY/V2RAY конфигурация с маскировкой секретов
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
  echo "xray/v2ray конфигурация не найдена в стандартных путях" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 10. Ключевые сервисы (активность)
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
  done
  echo
} >> "${OUTPUT_FILE}"

# 11. Автозапуск (enabled)
run "11. АВТОЗАПУСК СЕРВИСОВ (enabled)" bash -c "systemctl list-unit-files --state=enabled --type=service | grep -E 'ssh|xray|v2ray|fail2ban|firewall|cockpit' || true"

# 12. Активные соединения
run "12. АКТИВНЫЕ СОЕДИНЕНИЯ (ss -tun, топ-20)" bash -c 'ss -tun | head -20'

# 13. SSH конфигурация (без комментариев/пустых строк)
run "13. SSHD_CONFIG (очищено от комментариев)" bash -c 'grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config || true'

# 14. SSH: последние входы
run "14. SSH — Accepted (journalctl последние 200, затем хвост 20)" bash -c 'journalctl _COMM=sshd --no-pager 2>/dev/null | grep "Accepted" | tail -20'
run "14. SSH — Неудачные попытки (lastb -20)" bash -c 'lastb -20 2>/dev/null || true'

# 15. Пользователи с правами sudo
run "15. SUDO группы (wheel/sudo)" bash -c 'getent group wheel sudo 2>/dev/null || true'
run "15. SUDOERS файлы (/etc/sudoers.d)" bash -c 'ls -la /etc/sudoers.d/ 2>/dev/null || true'

# 16. SSH authorized_keys (root)
if [[ -f /root/.ssh/authorized_keys ]]; then
  {
    echo "=== 16. SSH AUTHORIZED_KEYS (root) ==="
    echo "Количество ключей у root:"
    wc -l /root/.ssh/authorized_keys
    echo "Fingerprints:"
    ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null || true
    echo
  } >> "${OUTPUT_FILE}"
else
  echo "=== 16. SSH AUTHORIZED_KEYS (root) ===" >> "${OUTPUT_FILE}"
  echo "Файл authorized_keys для root не найден" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 17. Cron задачи
run "17. Root crontab" bash -c 'crontab -l 2>/dev/null || true'
run "17. Системные cron.d" bash -c 'ls -la /etc/cron.d/ 2>/dev/null || true'

# 18. Обновления системы
if command -v apt >/dev/null 2>&1; then
  run "18. APT — доступные обновления" bash -c 'apt update -o Dir::Etc::sourcelist=/etc/apt/sources.list -o Dir::Etc::sourceparts=/etc/apt/sources.list.d/ -o DPkg::Lock::Timeout=30 >/dev/null 2>&1 || true; apt list --upgradable 2>/dev/null | sed "1d"'
  run "18. APT — security (по названию)" bash -c 'apt list --upgradable 2>/dev/null | grep -i security || true'
elif command -v yum >/dev/null 2>&1; then
  run "18. YUM — доступные обновления" bash -c 'yum check-update 2>/dev/null || true'
  run "18. YUM — security" bash -c 'yum updateinfo list security 2>/dev/null || true'
else
  echo "=== 18. ОБНОВЛЕНИЯ СИСТЕМЫ ===" >> "${OUTPUT_FILE}"
  echo "Менеджер пакетов (apt/yum) не найден" >> "${OUTPUT_FILE}"
  echo >> "${OUTPUT_FILE}"
fi

# 19. Подозрительные процессы
run "19. ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ (фильтр популярных системных)" bash -c 'ps aux | awk '\''$1 !~ /^(root|systemd|dbus|chrony|polkitd|rpc|xray|sshd|fail2ban|www-data|nginx|postgres|mysql|grafana|prometheus)$/ {print}'\'' | head -20'

# 20. SSH: PermitRootLogin
run "20. SSH — PermitRootLogin" bash -c 'grep -E "^PermitRootLogin" /etc/ssh/sshd_config || true'

# 21. Логи sudo
run "21. ЛОГИ SUDO (auth.log хвост)" bash -c 'tail -200 /var/log/auth.log 2>/dev/null | grep sudo | tail -20 || true'

# 22. Системные ошибки/предупреждения
run "22. DMESG хвост-20" bash -c 'dmesg | tail -20 || true'
run "22. JOURNALCTL — приоритет 3 (ошибки) хвост-20" bash -c 'journalctl -p 3 -xb --no-pager 2>/dev/null | tail -20 || true'

# 23. Пользователи системы
run "23. /etc/passwd (логин и shell)" bash -c 'awk -F: '\''{ print $1": "$7 }'\'' /etc/passwd'

# 24. SUID/SGID файлы
# Ограничим глубину: исключим большие каталоги, чтобы не зависнуть, и ограничим вывод
run "24. SUID/SGID файлы (топ-20)" bash -c 'find / -xdev -perm /6000 -type f 2>/dev/null | head -20'

# 25. Слушающие процессы и владельцы (сжатый вывод)
run "25. СЛУШАЮЩИЕ ПРОЦЕССЫ (ss кратко)" bash -c 'ss -tulnp | awk '\''{print $1, $5, $6, $7}'\'' | head -100'

# 26. Скрипты автозапуска
run "26. Автозапуск — /etc/rc.local" bash -c 'ls -la /etc/rc.local 2>/dev/null || true'
run "26. Автозапуск — /etc/init.d (топ-20)" bash -c 'ls -la /etc/init.d/ 2>/dev/null | head -20 || true'

# 27. Ядро и модули
run "27. Ядро (uname -r)" uname -r
run "27. Модули ядра (lsmod топ-20)" bash -c 'lsmod | head -20 || true'

# Завершение
{
  echo "=== СБОР ЗАВЕРШЁН ==="
  echo "Файл сохранён: ${OUTPUT_FILE}"
} >> "${OUTPUT_FILE}"

# Дополнительно: подсказка по упаковке результата
echo "Файл сохранён: ${OUTPUT_FILE}"
echo "Чтобы отправить отчёт, можно упаковать: tar -czf ${OUTPUT_FILE%.txt}.tar.gz ${OUTPUT_FILE}"
