# pscp
Pscp is a Python module for spawning scp application and auto login.

# Example
```python
import pscp
import getpass
s = pscp.pscp()
src = raw_input('src: ')
dst = raw_input('dst: ')
hostname = raw_input('hostname: ')
username = raw_input('username: ')
password = getpass.getpass('password: ')
try:
    s.to_server(src, dst, hostname, username, password)
except:
    pass
```
