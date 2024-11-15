#!/bin/bash
sed '/====================/,/\[Question Section\]/d' | \
    sed '/^$/d' | \
    sed '/^\[.*\]$/d' | \
    sed -E '/^(Timestamp:|SrcIP:|DstIP:|SrcPort:|DstPort:|Identifier:|Flags:|\(ROOT\))/d' | \
    uniq