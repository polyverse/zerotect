# polytect

An attack/exploit Detector that utilizes Polymorphism and Diversity.

Polytect relies on the fact that exploits are targeted to specific
languages, binaries and configurations.

If a programming language, binary or configuration is diverse, then
exploit attempts fail "loudly" (have clearly detectable side-effects).

Polytect detects these side effects of exploits on polymorphic systems.

## Usage

TBD 

## How it works

For now Polytect has the specific mandate:
1. Detect every process crash (initially segmentation faults) and report it.
2. Optionally collect a core dump of the process and report it.
3. Expose the segfaults and core dumps to a variety of endpoints, including metrics and logs.
