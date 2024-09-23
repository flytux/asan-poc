#!/bin/bash

scp artifacts/reset-remote-run.sh node-01:/root
ssh node-01 bash reset-remote-run.sh
