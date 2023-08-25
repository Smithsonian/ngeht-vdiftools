**[STRUCTURE][] | [GETTING STARTED][] | [RUNNING][] | [TESTING][]**

# vdif-tools
[r]: #repo

This repository contains VDIF-related tools. Initially, they were developed to facilitate
testing of the ngDBE (Digital Back End) by providing a way to extract VDIF data frames from
PCAP captures.

# Repository structure
[structure]: #repository-structure "Repository structure"

|Path|Description|Version-controlled|
|--|--|:--:|
| [examples/](./examples/)  | Contains example VDIF and PCAP files | Yes |
| [.gitignore](.gitignore)  | Lists what *not* to version control in this repository | Yes |
| [README.md](README.md)    | This file | Yes |
| [requirements.txt](requirements.txt)  | List of Python dependencies that must be installed | Yes |
| [mock-dbe.py](mock-dbe.py)  | Script that generates UDP streams of VDIF data frames | Yes |
| [pcap2vdif.py](pcap2vdif.py)  | Script that extracts VDIF data frames from PCAP captures | Yes |

# Getting Started
[getting started]: #getting-started "Getting Started"

These instructions will get a copy of the repository up and running on your local machine for
local development and use.

## Prerequisites

This section describes the things you need to build, test, and deploy the software and how to
install and configure them.

Required tools
* Git 2.3 or higher
* Python 3.9 or higher

## Setting up the environment

Here is a step by step guide to getting a development & execution environment up and running.
They are provided assuming a UNIX environment; some adaptation may be required if you are running
on another platform.

1. Create a Python virtual environment in a directory named `.venv` and activate it  
    _While you could do this without a virtual environment, it is not recommended_

    ```
    $ python -m venv .venv
    $ source .venv/bin/activate
    (.venv) $ python -m pip install --upgrade pip
    ```

1. Install any required Python modules

    ```
    (.venv) $ pip install -r requirements.txt
    ```

You are now ready to develop and execute the application.

# Running the software
[running]: #running-the-software "Running the software"

1. Assure you are within the Python virtual environment you created

    ```
    $ source .venv/bin/activate
    ```

1. Run any tool, providing any necessary commandline arguments. You can see a list of arguments
by running with the `-h` option.

    _This assumes you are in the same directory as this `README.md`_

    ```
    (.venv) $ python mock-dbe.py -h
    or
    (.venv) $ python pcap2vdif.py ethernet-vdifcap.pcap
    ```

# Testing the software
[testing]: #testing-the-software "Testing the software"

*Describe how to test the software. Use all pertinent sections below.*

## Manual tests

1. ### `mock-dbe.py` - *VDIF capture generation*
    1. Run Wireshark or tcpdump on your local machine to capture UDP traffic on a port of your
    choice  
    *(the default port is provided in the `-h` help for `mock-dbe.py`)*
    1. Run `mock-dbe.py` with the `sample.vdif` file from the `examples/` directory
        ```
        $ python mock-dbe.py examples/sample.vdif
        ```
        
    1. Save the output of Wireshark/tcpdump to a `.pcap` file
    1. Compare your `.pcap` file to the two `.pcap` files in the `examples/` directory; they should
    be similar. They won't be exactly the same since there is PCAP metadata throughout the file
    that can differ from machine to machine. But it should be obvious that there are large chunks
    of identical data which should correspond to the VDIF data frames.

1. ### `pcap2vdif.py` - *VDIF extraction*
    1. Run `pcap2vdif.py` on either of the `.pcap` files in the `examples/` directory
        ```
        $ python pcap2vdif.py examples/ethernet-vdifcap.pcap
        ```
    1. This should generate 8 `.vdif` files. You can individually compare them to
    `examples/sample.vdif`, or you can concatenate the 8 files together into a single file and
    compare that to `examples/sample.vdif`. Either way, each VDIF data frame should be identical.
