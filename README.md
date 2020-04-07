# Ribbit

I like writing shellcode, but I dont like testing it. Creating the standard `CreateThread` - `VirtualAlloc` program is exhausting. So I wrote this CLI cause its was like getting two birds with one stone: I wanna learn rust and I wanna write shellcode.

This is my first bit of rust code, be gentle 🥺.

## Usage

I think the CLI is pretty self explanatory, just `ribbit help`.

You can load your shellcode in two ways (currently):

1. As a hexadecimal string from the command prompt, with `ribbit-hexstring`
1. As a binary file from the disk with `ribbit-binfile`.

It also currently supports the `-b` flag, which adds a `\xCC` instruction to the begining of the shellcode, which can help you if you have post-mortem debugging enabled.

If you wanna debug your 32 bit shellcode make sure youre building `ribbit` to 32 bit!

## Internals

It just does what it says - it takes a payload, allocates RWE memory using `VirtualAlloc`, and then `CreateThread` having its `lpStartAddress` be the start of that memory. `ribbit` then `WaitForSingleObject`s on that thread, `VirtualFree`ing the mapped memory, terminating afterwards.

## TODO

* Change the `VirtualAlloc` memory stuff to a `impl Drop` for automatic cleanup using `VirtualFree`.
* Change the `CreateThread` `HANDLE` stuff to a `impl Drop` for automatic handle cleanup using `CloseHandle`.
* Wrap the `HANDLE` and `[u8]` with actual safe structures.
* Consider supporting more input options:
  * Raw assembly?
* More source code files!
