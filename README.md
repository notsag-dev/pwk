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
#### Grep
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

### awk
```echo "hello::there::friend" | awk -F "::" '{print $1, $3}'```
