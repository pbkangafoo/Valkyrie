![logo](https://github.com/pbkangafoo/valkyrie/blob/main/logo_valk.JPG "valkyrie logo")

# Valkyrie
Support tool for local privilege escalation on linux machines.

Version: 0.1

## What is Valkyrie?

Valkyrie supports you finding possibilities for local privilege escalation by:
- detecting kernel version and recommending local exploits
- finding suid binaries
- finding interesting files you can read

Future features will be added.

## Usage

At this point, rootme supports two ways for recommending local exploits:

Detect kernel and suggest exploit:

> python valkyrie.py -d

Manually name the version of the kernel:

> python valkyrie.py -m 4.4.2

Finding binaries with suid permission:

> python valkyrie.py -s

Finding interesting files and checking whether you can read them:

> python valkyrie.py -r

## Exploit database

the exploit database is currently quite limited and only contains 5 entries. In the next versions, the database will be extended.

## Screenshot

![Screenshot](https://github.com/pbkangafoo/valkyrie/blob/main/screenshot_valk.JPG "valkyrie screenshot")
