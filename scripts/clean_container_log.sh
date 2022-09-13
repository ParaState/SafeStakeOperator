#!/bin/bash

log_path=$(sudo docker inspect --format='{{.LogPath}}' $1)
sudo truncate -s 0 $log_path