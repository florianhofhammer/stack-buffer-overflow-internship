---
pagetitle:  README for the setup and usage of the repository
author:     Florian Hofhammer
date:       2020-04-24
---

This repository contains the code and documentation for the Stack Buffer Overflow research internship with INRIA Sophia Antipolis.

The main documentation work is conducted in the [NOTES.md](./NOTES.md) (HTML rendered version [here](./NOTES.html)).
The Markdown files of this repository are rendered to HTML files using [pandoc](https://pandoc.org).
For pretty formatting, the [GitHub.html5](./Misc/GitHub.html5) template located in the Misc subdirectory is used.
The version used here is a slightly adapted version of a [template found on GitHub](https://github.com/tajmone/pandoc-goodies/blob/master/templates/html5/github/GitHub.html5).   
To automatically render the Markdown files to HTML, a `git commit` hook is used.
The [corresponding script file](./Misc/pre-commit) is also found in the Misc subdirectory and has to be copied to the `.git/hooks` directory to become active.
