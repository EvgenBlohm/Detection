
rule SUSP_LNK_CMD {
	meta:
		author = "https://github.com/EvgenBlohm/Detection"
		description = "Detects LNK Files that call to cmd.exe"
		date = "07.09.2022"
		reference = "https://bazaar.abuse.ch/sample/3ba32825177d7c2aac957ff1fc5e78b64279aeb748790bc90634e792541de8d3/"

	strings:
		$lnk_header = {4c 00 00 00 01 14 02 00}

		$cmd = "cmd.exe" ascii wide

	condition:
		$lnk_header at 0 and $cmd

}

rule SUSP_LNK_cURL {
	meta:
		author = "https://github.com/EvgenBlohm/Detection"
		description = "Detects LNK Files that call to cmd.exe"
		date = "07.09.2022"
		reference = "https://bazaar.abuse.ch/sample/3ba32825177d7c2aac957ff1fc5e78b64279aeb748790bc90634e792541de8d3/"

	strings:
		$lnk_header = {4c 00 00 00 01 14 02 00}

		$curl = "curl" ascii wide
	
	condition:
		$lnk_header at 0 and $curl
}

