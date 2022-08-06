import "pe"

rule SUSP_Compiled_VB {
	meta:
		author = "https://github.com/EvgenBlohm/Detection"
		date = "07.09.2022"
		description = "Detects a compiled VB Script by import. Does not necessarly need to be a malware"
		reference = "https://bazaar.abuse.ch/sample/8641e15c78f1ce0512d18e2bf90539ff8df008e4092b001cda6ca0cebd99ae25/"

	strings:
		$pe_header = {4d 5a}

	condition:
		$pe_header at 0 and pe.imports("MSVBVM60.dll")
}