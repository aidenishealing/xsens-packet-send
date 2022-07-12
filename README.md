xsens-packet-send
=================

Since XSENS software is stupidly expensive and restrictive, we've written this piece of software to send 
network packets to Unreal Engine. It cuts out the need for running MVN Animate Pro (which costs thousands 
of dollars a year).

Windows installation
--------------------

1. [Install the Rust programming language compiler](https://www.rust-lang.org/tools/install).
   On Windows, you'll probably want 64-bit for modern machines.

2. The Rust compiler will need Microsoft's C++ compiler and linker.
   [This Microsoft guide](https://docs.microsoft.com/en-us/windows/dev-environment/rust/setup) explains how
   to install support along with Visual Studio.

Running the program on Windows
------------------------------

1. Open `cmd` (command line) or `PowerShell.exe`. 

2. Use `cd` ("change directory") to find the location of the program. 
   `dir` can be used to see the current directory contents.

3. Type `cargo run` to run the program in debug mode (fast compile, slow execution). 
   Ctrl-C will kill the program without needing to close the terminal.

4. Type `cargo build --release` to build a production `.exe` binary file that will run
   six times faster. The exe file will be under the subdirectory `target/release/`.

