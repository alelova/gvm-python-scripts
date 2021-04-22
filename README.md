# gvm-python-scripts
Some scripts to get gvm info, hosts, vulnerabilities, and get a latex report.

Some previus configuration

The user must have permission to read the socket gvmd

in kali, and other linux:
```
usermod -aG _gvmd user
```

Config your gvm conection in .config/gvm-tools.config
```
[gmp]
username=admin
password=yourpassword
[unixsocket]
socketpath=/var/run/gvm/gvmd.sock
```

run the scripts
```
gvm-script socket python/monthly-report-latex.gmp.py 04 2021
```
