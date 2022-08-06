
rule OBFUS_JS_XMLHTTP_Base64 {
	meta:
		author = "https://github.com/EvgenBlohm/Detection"
		description = "Detect Base64 encoded keyword xmlhttp that can be used to perform HTTP requests in JavaScript"
		date = "06.09.2022"
		reference = "Internal Research"

	strings:
		$s1 = "eG1saHR0c"
		$s2 = "htbGh0dH"
		$s3 = "4bWxodHRw"

	condition:
		filesize < 30kb and 1 of $s*
}