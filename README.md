![session](resources/2021-11-06_12-23.png?raw=true)

Intellivoid PAM module
=====

This PAM module prints the state of the system, warning banner, and logos upon login. 

It also logs all changes of privilege (logins, sudo uses, etc.) and sends notifications to the relevant people.

Building
-----

To build run the following commands:

**Build the PAM module**

```bash
mkdir build; cd build; cmake ..; make package
```
or 
```bash
mkdir build; cd build; cmake ..; make
```

**Build Test**

`gcc -o pam_test src/test.c -lpam -lpam_misc`

Installation
------------

The build scripts will take care of putting your module where it needs to be, `/lib/security`.
You should only need to build and install the .rpm file. Alternatively you can manually copy `pam_intellivoid.so` to the install location.

The config files are located in `/etc/pam.d/`, find the relevant configurations and at the top of the pam file (or anywhere), put these lines:

	auth    optional pam_intellivoid.so
	account optional pam_intellivoid.so


Test program
-------------

To run the test program, just do: `pam_test backdoor` and you should get some messages saying that you're authenticated! Maybe this is how Sam Flynn 'hacked' his father's computer in TRON Legacy =D.
