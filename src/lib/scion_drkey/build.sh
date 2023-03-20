#!/usr/bin/env bash
set -Eeuo pipefail

rm -f libdrkey.a libdrkey.h
go build -buildmode=c-archive -o libdrkey.a drkey.go
