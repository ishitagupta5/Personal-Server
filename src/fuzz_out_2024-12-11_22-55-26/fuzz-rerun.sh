#!/bin/bash

# variables
preload=/home/courses/cs3214/bin/sfi/gurthang/gurthang-preload.so
server=/home/ugrads/majors/ishitagupta/CS3214/pserv/src/server-fuzz

# input check
if [ $# -lt 1 ]; then
    echo "Usage: $0 /path/to/crash/file"
    exit 1
fi
fpath=$1

# running
LD_PRELOAD=${preload} ${server} -p 40769 -R /home/ugrads/majors/ishitagupta/CS3214/pserv/src/fuzz_root  < ${fpath}
