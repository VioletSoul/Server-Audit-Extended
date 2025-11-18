# Server Audit Extended

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-FF6600?style=flat&logo=ubuntu&logoColor=white)
![Security](https://img.shields.io/badge/Security-Audit-blue)
![License](https://img.shields.io/badge/License-MIT-blue)
![Repo Size](https://img.shields.io/github/repo-size/VioletSoul/server-audit)
![Code Size](https://img.shields.io/github/languages/code-size/VioletSoul/server-audit)
[![Stars](https://img.shields.io/github/stars/VioletSoul/server-audit.svg?style=social)](https://github.com/VioletSoul/server-audit)
[![Last Commit](https://img.shields.io/github/last-commit/VioletSoul/server-audit.svg)](https://github.com/VioletSoul/server-audit/commits/main)

**Server Audit Script** is a Bash script for comprehensive Linux server auditing, gathering system info, resource stats, network settings, firewall status, and security logs.

---

## Main Features

- Collects system and Linux kernel information
- Monitors CPU, memory, and disk usage
- Lists active network interfaces and open ports
- Checks UFW rules and Fail2Ban status
- Collects sshd logs and suspicious activity
- Generates a timestamped text audit report

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
4. The audit report will be generated in the current directory with a timestamped filename like `server_audit_YYYYMMDD_HHMMSS.txt`
5. To copy the report to your local machine (MacBook), use:  
```
scp user@server:~/server_audit_YYYYMMDD_HHMMSS.txt ~/Downloads/
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
