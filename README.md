# Server Audit Extended

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-FF6600?style=flat&logo=ubuntu&logoColor=white)
![Security](https://img.shields.io/badge/Security-Audit-blue)
![License](https://img.shields.io/badge/License-MIT-blue)
![Repo Size](https://img.shields.io/github/repo-size/VioletSoul/server-audit)
![Code Size](https://img.shields.io/github/languages/code-size/VioletSoul/server-audit)
[![Stars](https://img.shields.io/github/stars/VioletSoul/server-audit.svg?style=social)](https://github.com/VioletSoul/server-audit)
[![Last Commit](https://img.shields.io/github/last-commit/VioletSoul/server-audit.svg)](https://github.com/VioletSoul/server-audit/commits/main)

**Server Audit Extended Script** is a Bash script for comprehensive Linux server auditing, gathering system info, resource stats, network settings, firewall status, and security logs.

---

## Key Features

- ✅ Collects system metadata: OS, kernel, uptime, and hardware info
- ✅ Monitors CPU, memory, and disk usage for performance analysis
- ✅ Lists active network interfaces and all listening ports
- ✅ Audits firewall configurations: **iptables**, **nftables**, **UFW**, **firewalld**
- ✅ Checks **Fail2Ban** status and banned IPs
- ✅ Analyzes SSH configuration and logs for suspicious activity
- ✅ Generates **timestamped audit reports** in both human-readable text and JSON for automated parsing
- ✅ Masks sensitive data (keys, passwords) in configuration files for safe sharing

---

## Requirements

- Linux server (preferably Ubuntu 25.04 or compatible)
- Bash shell
- Sudo privileges for accessing system info and settings
- Recommended packages: `ufw`, `fail2ban`

---

## Usage

1. Copy the script to your server, e.g.:  
```
scp collect_info.sh user@server:~/
```
2. Make it executable:  
```
chmod +x collect_info.sh
```
3. Run with sudo:  
```
sudo ./collect_info.sh
```
4. Audit report (the script generates two files in the current directory with timestamped filenames)
```
Plain text report: server_audit_YYYYMMDD_HHMMSS.txt
JSON report: server_audit_YYYYMMDD_HHMMSS.json
```
5. To copy the report to your local machine (MacBook), use:  
```bash
scp 'root@server:~/server_audit_*' ~/Downloads/
```

---

## Example Output

The report contains info about:

- OS and kernel versions
- Resource usage (CPU, RAM, disks)
- Network interfaces and open ports
- Firewall rules and Fail2Ban status
- sshd logs and access attempts

---

## Contributing

Contributions and suggestions are welcome. Please open issues or pull requests.

---

## License

MIT License

---

## Contact

If you have questions or suggestions, please open an issue in the repository.

---

**Server Audit Script** is a reliable tool for sysadmins and security specialists for quick diagnostics and server auditing.
