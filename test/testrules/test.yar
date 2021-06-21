rule ExcludedRule
{
	strings:
		$c0 = /test/
	condition:
		$c0
}

rule IncludedRule
{
	strings:
		$c0 = /test/
}
