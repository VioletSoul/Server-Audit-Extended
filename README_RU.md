# Server Audit Extended

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-FF6600?style=flat&logo=ubuntu&logoColor=white)
![Security](https://img.shields.io/badge/Security-Audit-blue)
![License](https://img.shields.io/badge/License-MIT-blue)
![Repo Size](https://img.shields.io/github/repo-size/VioletSoul/server-audit)
![Code Size](https://img.shields.io/github/languages/code-size/VioletSoul/server-audit)
[![Stars](https://img.shields.io/github/stars/VioletSoul/server-audit.svg?style=social)](https://github.com/VioletSoul/server-audit)
[![Last Commit](https://img.shields.io/github/last-commit/VioletSoul/server-audit.svg)](https://github.com/VioletSoul/server-audit/commits/main)

**Server Audit Extended Script** — это Bash-скрипт для комплексного аудита Linux-серверов: сбор системной информации, ресурсов, сетевых настроек, статуса файрвола и журналов безопасности.

---

## Основные возможности

- Сбор информации о системе и ядре Linux
- Мониторинг использования CPU, памяти и дисков
- Список активных сетевых интерфейсов и открытых портов
- Проверка правил UFW и статуса Fail2Ban
- Сбор логов sshd и подозрительной активности
- Генерация текстового отчёта аудита с временной меткой

---

## Требования

- Linux-сервер (предпочтительно Ubuntu 25.04 или совместимый)
- Bash
- Права sudo для доступа к системным параметрам
- Рекомендуемые пакеты: `ufw`, `fail2ban`

---

## Использование

1. Скопируйте скрипт на сервер, например:
```bash
scp collect_info.sh user@server:~/
```

2. Сделайте исполняемым:
```bash
chmod +x collect_info.sh
```

3. Запустите с sudo:
```bash
sudo ./collect_info.sh
```

4. Отчёт будет создан в текущем каталоге под именем вида  
   `server_audit_YYYYMMDD_HHMMSS.txt`

5. Чтобы скачать отчёт на локальную машину (MacBook):
```bash
scp user@server:~/server_audit_YYYYMMDD_HHMMSS.txt ~/Downloads/
```

---

## Пример содержимого отчёта

Отчёт включает:

- Версии ОС и ядра
- Использование ресурсов (CPU, RAM, диски)
- Сетевые интерфейсы и открытые порты
- Правила файрвола и статус Fail2Ban
- Логи sshd и попытки доступа

---

## Contributing

Предложения и улучшения приветствуются.  
Пожалуйста, открывайте issues или pull-requests.

---

## Лицензия

MIT License

---

## Контакт

Если у вас есть вопросы или предложения — создайте issue в репозитории.

---

**Server Audit Script** — это надёжный инструмент для администраторов и специалистов по безопасности для быстрой диагностики и аудита серверов.
