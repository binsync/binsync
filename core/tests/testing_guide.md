# Testing Guide

## Automated Tests
Run `pytest` above this directory and it will run both the UI and Core tests.

## Manual Testing
Often for BinSync it can be useful to test some basic functionallities when you
a change to one of the plugins. Below are some of the things you should do.

### Verify README example still works 
Just follow the verification for pulling down data from the `main` function of 
the `fauxware` binary for the `binsync_example_repo`. 

### Verify Writing and Reading on your own repo
1. Make a repo from scratch, preferably with a GitHub remote active
2. Do some writing changes from one user, verify they make it to remote
3. Do some reading from the first user, verify they make it to you, your remote,
   and do not show up as "new" changes for user 2. 

### Verify Non-standard Writes
Sometimes I get some crashes if I just test non-standard order of thinking.
Try this for example:
1. User1 changes the name of a stack var in a function he has not named yet
2. User2 pulls that change
3. Verify User2 did not get their function name changed

Do this for what you think is affected, like comments, function args,
and maybe even structs if we have an association system for funcs and structs.

