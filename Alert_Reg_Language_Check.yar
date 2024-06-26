rule Alert_Reg_Language_Check {
	meta:
		author = "The Professor"
		date = "2024-04-20"
	strings:
		$command = "reg query"
		$reg = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\"
		 $suspicious_change = "change"
    		$suspicious_set = "set"
    		$suspicious_modify = "modify"        
		$l1 = "042B" //Aremenian
		$l2 = "042C" //Azerbaijan
        	$l3 = "0423" //Belarus
		$l4 = "043F" //Kazakhstan
		$l5 = "0440" //Kyrgyzstan
		$l6 = "0419" //Russia
		$l7 = "042" //Tajikistan
		$l8 = "0443" //Uzbekistan(Latin)
		$l9 = "0843" //Uzbekistan(Cyrillic)		
	condition:
		$command and $reg and ( $suspicious_change or $suspicious_set or $suspicious_modify ) and 1 of ($l* )  
}
