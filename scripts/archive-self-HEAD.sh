#!/bin/bash

OUT=../parmesan-`git rev-parse --short HEAD`.tar

git archive HEAD -o $OUT

# if needed to delete particular file: tar -f $OUT --delete file

gzip $OUT
