# Contributing

Please note we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Contributing Process
1. Read about what kind of contributions we look for and will accept in the section below.
2. Before doing any work, file an issue to explain the problem you're trying to solve and how you intend to solve it. 
   It can save a lot of effort and frustration to discuss what you intend to do and whether it will be merged.
3. Submit a PR with changes. If a charge is very large or disruptive, we prefer keeping the overarching issue open,
   and submitting smaller focussed PRs that build up to the feature. This helps each PR build incrementally on the others
   and keeps cognitive load low.

## What we accept

1. We accept pretty much ALL contributions so long as:
   (a) They don't break an existing use-case or dependant
   (b) They don't do something that is wildly out of scope of the project.
2. We don't have extensive coding guidelines and pretty much everything goes so long as:
   (a) It is safe rust and reasonable.
   (b) There are extensive UTs to define the feature.
   (c) You may use `cargo fmt` for formatting. It's not perfect and it can be downright ugly. But it's consistent.
3. For Zerotect, Unit Tests are documentation where truth is captured. What kinds of events does it parse? What formats
   does it emit in? What config flags does it support? All answers are found in UTs.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Once approved, the reviewer will merge your Pull Request.

## Reporting a Bug

1. Install the latest version of Zerotect, and try to reproduce the bug. You can find installation and uninstallation 
   instructions [here](install/README.md).
2. Look at our [issue tracker](https://github.com/polyverse/zerotect/issues) to make sure someone else hasn't reported the same bug.
3. If nobody else has reported the issue, create a bug report! Use the following format:
   - Hardware, distro, distro version, Zerotect version used
   - Expected behavior
   - Actual behavior
   - Repro steps
