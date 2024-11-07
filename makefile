SHELL_PATH = /bin/ash
SHELL = $(if $(wildcard $(SHELL_PATH)),/bin/ash,/bin/bash)

# this makefile ensure to Deploy | Install dependencies| Tooling | 
# Running Test | Running The Project | genrate Keys | Building containers