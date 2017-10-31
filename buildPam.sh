#!/bin/bash

clang++ -shared -o pam_sysinfo.so -std=c++17 -fPIC -rdynamic -fno-stack-protector src/pam_sysinfo.cpp -lpam -ldl -lembedFiglet

sudo install pam_sysinfo.so /lib/security/pam_sysinfo.so
#sudo ld -x --shared -o /lib/security/pam_sysinfo.so pam_sysinfo.o

#rm mypam.o
