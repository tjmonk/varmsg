# varmsg

Variable Message Generator

The varmsg service generates variable messages and sends them
to a specified output whenever the send conditions are met.

The message generate can build multiple messages, each one governed
by an input configuration file, which is loaded and processed when
the services is started.

The message generator builds its messages based on a local VarCache.

The VarCache can be built manually, or from a variable query.

The output type is configurable, and can be one of:

- standard output (used for testing)
- output file
- message queue

Each configuration may have a variable prefix associated with it,
and exposes status and control variables to change the behavior at
runtime.  For example if the variable prefix for a variable message
is /msg1, then the following variables will be available:

/msg1/txcount - counts the number of generations/transmissions
/msg1/errcount - counts the number of errors during generation/transmission
/msg1/enable - enables or disables sending the data
/msg1/rescan - forces a re-generation of variable sets

Each configuration is configured using a JSON configuration file
loaded from the configuration directory on startup.

It has the following settings:

prefix : message prefix for control/status variables
interval : generation interval (seconds) (optional)
triggers : query or variable list (optional)
outputset : query or variable list
outputtype : one of stdout, file, mqueue
header : location of header template file

An example configuration is shown below:

{
    "enabled" : true,
    "output_type" : "mqueue",
    "output" : "/splunk",
    "prefix" : "/varmsg/msg1/",
    "header" : "/usr/share/headers/header1",
    "interval" : 60,
    "trigger" : {
        "tags" : "test",
        "flags" : "volatile"
    },
    "vars" : {
        "tags" : "test"
    }
}
