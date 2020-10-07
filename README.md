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
