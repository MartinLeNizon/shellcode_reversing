private rule is_pe {
	meta:
		description = "PE executable"

	strings:
		$mz = { 4D 5A }

	condition:
		$mz at 0
}

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


