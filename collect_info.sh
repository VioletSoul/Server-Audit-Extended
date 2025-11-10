#!/bin/bash
# Скрипт сбора информации о VPS для анализа безопасности (совместим с cloud/OVH Ubuntu)

OUTPUT_FILE="server_audit_$(date +%Y%m%d_%H%M%S).txt"

if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запускайте этот скрипт через sudo или от имени root."
  exit 1
fi

echo "=== СБОР ИНФОРМАЦИИ О СЕРВЕРЕ ===" > $OUTPUT_FILE
echo "Дата: $(date)" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 1. ИНФОРМАЦИЯ О СИСТЕМЕ ===" >> $OUTPUT_FILE
uname -a >> $OUTPUT_FILE
cat /etc/os-release >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "Uptime и загрузка:" >> $OUTPUT_FILE
uptime >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 2. ИСПОЛЬЗОВАНИЕ РЕСУРСОВ ===" >> $OUTPUT_FILE
echo "--- Память ---" >> $OUTPUT_FILE
free -h >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- Диск ---" >> $OUTPUT_FILE
df -h >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- CPU загрузка (последние 5 процессов) ---" >> $OUTPUT_FILE
ps aux --sort=-%cpu | head -6 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 3. СЕТЕВЫЕ ИНТЕРФЕЙСЫ ===" >> $OUTPUT_FILE
ip addr show >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 4. ОТКРЫТЫЕ ПОРТЫ ===" >> $OUTPUT_FILE
ss -tulpn >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 5. ПРАВИЛА FIREWALL (iptables) ===" >> $OUTPUT_FILE
echo "--- INPUT chain (основные правила) ---" >> $OUTPUT_FILE
sudo iptables -L INPUT -n -v --line-numbers | head -30 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- FORWARD chain (основные правила) ---" >> $OUTPUT_FILE
sudo iptables -L FORWARD -n -v --line-numbers | head -30 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- OUTPUT chain (основные правила) ---" >> $OUTPUT_FILE
sudo iptables -L OUTPUT -n -v --line-numbers | head -30 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- Статистика fail2ban цепочек (без списка IP) ---" >> $OUTPUT_FILE
sudo iptables -L -n -v | grep -E '^Chain f2b-|^[0-9]' | grep -v 'DROP.*all' | head -50 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 6. ПРАВИЛА FIREWALL (firewalld если активен) ===" >> $OUTPUT_FILE
if systemctl is-active --quiet firewalld; then
    echo "Firewalld активен:" >> $OUTPUT_FILE
    firewall-cmd --list-all >> $OUTPUT_FILE
else
    echo "firewalld не активен" >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 7. ПРАВИЛА FIREWALL (ufw если установлен) ===" >> $OUTPUT_FILE
if command -v ufw &> /dev/null; then
    sudo ufw status verbose >> $OUTPUT_FILE
else
    echo "ufw не установлен" >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 8. FAIL2BAN СТАТУС ===" >> $OUTPUT_FILE
if command -v fail2ban-client &> /dev/null; then
    sudo fail2ban-client status >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    for jail in $(sudo fail2ban-client status | grep "Jail list" | sed "s/.*://;s/,//g"); do
        echo "--- Jail: $jail ---" >> $OUTPUT_FILE
        sudo fail2ban-client status $jail | grep -E 'Currently banned|Total banned' >> $OUTPUT_FILE
    done
    echo "" >> $OUTPUT_FILE
    echo "--- Последние 10 событий fail2ban ---" >> $OUTPUT_FILE
    tail -20 /var/log/fail2ban.log 2>/dev/null | grep -i "ban" >> $OUTPUT_FILE
else
    echo "fail2ban не установлен" >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 9. XRAY/V2RAY КОНФИГУРАЦИЯ ===" >> $OUTPUT_FILE
if [ -f /usr/local/etc/xray/config.json ]; then
    echo "Найден xray config.json" >> $OUTPUT_FILE
    sudo cat /usr/local/etc/xray/config.json | sed 's/"id": "[^"]*"/"id": "MASKED_UUID"/g' | sed 's/"password": "[^"]*"/"password": "MASKED_PASS"/g' | sed 's/"privateKey": "[^"]*"/"privateKey": "MASKED_KEY"/g' >> $OUTPUT_FILE
elif [ -f /etc/xray/config.json ]; then
    echo "Найден xray config.json (альтернативный путь)" >> $OUTPUT_FILE
    sudo cat /etc/xray/config.json | sed 's/"id": "[^"]*"/"id": "MASKED_UUID"/g' | sed 's/"password": "[^"]*"/"password": "MASKED_PASS"/g' | sed 's/"privateKey": "[^"]*"/"privateKey": "MASKED_KEY"/g' >> $OUTPUT_FILE
else
    echo "xray конфигурация не найдена в стандартных путях" >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 10. КЛЮЧЕВЫЕ СЕРВИСЫ ===" >> $OUTPUT_FILE
echo "Проверка важных для безопасности сервисов:" >> $OUTPUT_FILE
for service in ssh sshd xray v2ray fail2ban ufw iptables firewalld cockpit; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo "✓ $service - АКТИВЕН" >> $OUTPUT_FILE
    fi
done
echo "" >> $OUTPUT_FILE

echo "=== 11. АВТОЗАПУСК СЕРВИСОВ (enabled) ===" >> $OUTPUT_FILE
systemctl list-unit-files --state=enabled --type=service | grep -E 'ssh|xray|fail2ban|firewall|cockpit' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 12. АКТИВНЫЕ СОЕДИНЕНИЯ ===" >> $OUTPUT_FILE
ss -tun | head -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 13. SSH КОНФИГУРАЦИЯ ===" >> $OUTPUT_FILE
sudo cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 14. SSH: ПОСЛЕДНИЕ ВХОДЫ ===" >> $OUTPUT_FILE
echo "--- Последние успешные входы через journalctl ---" >> $OUTPUT_FILE
journalctl _COMM=sshd | grep "Accepted" | tail -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- Неудачные попытки входа (lastb) ---" >> $OUTPUT_FILE
sudo lastb -20 2>/dev/null >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 15. ПОЛЬЗОВАТЕЛИ С ПРАВАМИ SUDO ===" >> $OUTPUT_FILE
echo "--- Группа wheel/sudo ---" >> $OUTPUT_FILE
getent group wheel sudo 2>/dev/null >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- Sudoers файлы ---" >> $OUTPUT_FILE
ls -la /etc/sudoers.d/ 2>/dev/null >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 16. SSH АВТОРИЗОВАННЫЕ КЛЮЧИ (root) ===" >> $OUTPUT_FILE
if [ -f /root/.ssh/authorized_keys ]; then
    echo "Количество ключей у root:" >> $OUTPUT_FILE
    wc -l /root/.ssh/authorized_keys >> $OUTPUT_FILE
    echo "Fingerprints:" >> $OUTPUT_FILE
    ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null >> $OUTPUT_FILE
else
    echo "Файл authorized_keys для root не найден" >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 17. CRON ЗАДАЧИ ===" >> $OUTPUT_FILE
echo "--- Root crontab ---" >> $OUTPUT_FILE
crontab -l 2>/dev/null >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--- Системные cron.d ---" >> $OUTPUT_FILE
ls -la /etc/cron.d/ 2>/dev/null >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 18. ОБНОВЛЕНИЯ СИСТЕМЫ ===" >> $OUTPUT_FILE
if command -v apt &> /dev/null; then
    UPDATE_COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    echo "Доступно обновлений: $UPDATE_COUNT" >> $OUTPUT_FILE
    echo "Критические обновления безопасности:" >> $OUTPUT_FILE
    apt list --upgradable 2>/dev/null | grep -i security | head -10 >> $OUTPUT_FILE
elif command -v yum &> /dev/null; then
    UPDATE_COUNT=$(yum check-update 2>/dev/null | grep -c "^[a-zA-Z]")
    echo "Доступно обновлений: $UPDATE_COUNT" >> $OUTPUT_FILE
    echo "Критические обновления безопасности:" >> $OUTPUT_FILE
    yum updateinfo list security 2>/dev/null | head -10 >> $OUTPUT_FILE
fi
echo "" >> $OUTPUT_FILE

echo "=== 19. ПРОВЕРКА НА ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===" >> $OUTPUT_FILE
echo "--- Процессы от неизвестных пользователей ---" >> $OUTPUT_FILE
ps aux | awk '$1 !~ /^(root|systemd|dbus|chrony|polkitd|rpc|xray|sshd|fail2ban)$/ {print}' | head -10 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Дополнительные секции (предложения)
echo "=== 20. SSH: Вход по root ===" >> $OUTPUT_FILE
grep "^PermitRootLogin" /etc/ssh/sshd_config >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 21. ЛОГИ SUDO ===" >> $OUTPUT_FILE
tail -20 /var/log/auth.log | grep sudo >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 22. СИСТЕМНЫЕ ОШИБКИ И ПРЕДУПРЕЖДЕНИЯ ===" >> $OUTPUT_FILE
dmesg | tail -20 >> $OUTPUT_FILE
journalctl -p 3 -xb | tail -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 23. ПОЛЬЗОВАТЕЛИ СИСТЕМЫ ===" >> $OUTPUT_FILE
cat /etc/passwd | awk -F: '{ print $1": "$7 }' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 24. SUID/SGID ФАЙЛЫ ===" >> $OUTPUT_FILE
find / -perm /6000 -type f 2>/dev/null | head -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 25. СЛУШАЮЩИЕ ПРОЦЕССЫ И ВЛАДЕЛЬЦЫ ===" >> $OUTPUT_FILE
ss -tulnp | awk '{print $1, $5, $6, $7}' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 26. Скрипты автозапуска ===" >> $OUTPUT_FILE
ls -la /etc/rc.local 2>/dev/null >> $OUTPUT_FILE
ls -la /etc/init.d/ 2>/dev/null | head -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== 27. Ядро и модули ===" >> $OUTPUT_FILE
uname -r >> $OUTPUT_FILE
lsmod | head -20 >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

echo "=== СБОР ЗАВЕРШЁН ===" >> $OUTPUT_FILE
echo "Файл сохранён: $OUTPUT_FILE"
