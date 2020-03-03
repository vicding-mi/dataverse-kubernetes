#!/bin/bash

# Creating new folders for /data, /docroot, glassfish and solr 
mkdir /mnt/disks
mkdir /mnt/disks/ssd1
mkdir /mnt/disks/ssd2
mkdir /mnt/disks/ssd3
mkdir /mnt/disks/ssd4
# Declare local volumes bound on created folders
kubectl apply -f ./volumes/local/pv.yaml
