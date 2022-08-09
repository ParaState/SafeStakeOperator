#!/bin/sh
cat /data/dvf_root.log | grep "Base64" | cut -d" " -f3 > /data/enr_info.log