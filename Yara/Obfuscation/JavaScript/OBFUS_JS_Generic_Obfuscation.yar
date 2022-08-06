
rule OBUFS_JS_String_Manipulation_August_22 {
	meta:
		author = "https://github.com/EvgenBlohm/Detection"
		description = "Detects JavaScript Obfuscation by usage of function like toString etc."
		date = "06.09.2022"
		reference = "https://bazaar.abuse.ch/sample/376180cf80a62085441a0b2a19e9b0fb2abdf3e1020955cfc4bd549e4bcc6726/"

	strings:
		$s1 = "toString("
		$s2 = "fromCharCode("
		$s3 = "charCodeAt("

	condition:
		filesize < 30KB and (#s1 > 2 or #s2 > 2 or #s3 > 2)
}