#!/bin/bash

# Script to sync local changes and remote code of SD-VBS benchmarks

rsync -a --progress ./ zcu102:sd-vbs
