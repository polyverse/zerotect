Making sense of ZeroTect logs
=============================

# ZeroTect log file location

On most default installations, ZeroTect records logs at:
```
/var/log/zerotect.log
```


# Zerotect Log Entry types

Zerotect interprets two primary types of kernel logs:

## Linux Kernel Traps
Kernel traps are fewer in frequency and trap illegal program behavior such as a Segmentation Fault (writing to memory pages not allocated) or General Protection Fault and any number of other traps. Traps tell you a few things like:
1. What process it occurred in (procname)
2. What the Instruction Pointer was (ip)
3. What the Stack Pointer was (sp)

## Linux Fatal Signals
Linux fatal signals are similar to traps but don't necessarily have structured data. They contain a set of Key-Value pairs, many of which are values of Registers at the time the fatal was recorded.

These register values give us a clue into whether or not each Fatal was identical or different.
