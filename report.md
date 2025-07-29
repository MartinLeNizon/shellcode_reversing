# Analysis of a shellcode

```
func_pointer.bin64: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 11 sections
SHA256: edd41b4a819f917f81203424730aaf0c24cc95e40acfc0f1bd90b11dadf58015
```

## Basic static analysis

The sample is only 24 kB and targeting x64 Windows systems. It is probably not packed or heavily obfuscated, at least not in a way that significantly expands its file size. A small size often suggests either a very simple piece of malware, a loader/dropper that downloads a larger payload, or a highly optimized and potentially assembly-heavy piece of code. This small footprint also implies it might not contain a large amount of embedded resources or complex libraries. Therefore, we should be able to begin direct analysis of its code without extensive unpacking efforts.

Opening the file in Die [](assets/die_compiler.png), we see that the the program has been written in C/C++, using MinGW compiler. We can even retrieve the compilation timestamp (in pestudio or CFF Explorer): `2023-04-06 15:21:17`.

## Detailed static analysis


