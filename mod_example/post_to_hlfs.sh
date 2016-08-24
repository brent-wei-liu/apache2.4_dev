#!/bin/sh

URL=http://beta02.hlfs.bf1.yahoo.com:4080/V4/HLFSWebService
FILE=$1

cat $FILE | curl -v -X POST -H 'Content-type: application/x-protobuf' --data-binary @- $URL


