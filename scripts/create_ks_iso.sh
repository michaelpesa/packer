#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 [operating system]"
  exit 1
fi

mkisofs -V OEMDRV -o "${1}_ks.iso" "${1}_ks.cfg"
