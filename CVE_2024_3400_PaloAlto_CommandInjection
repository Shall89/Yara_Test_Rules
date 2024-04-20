rule CVE_2024_3400_PaloAlto_CommandInjection {
 meta:
  description = "Yara rule for CVE-2024-3400 Palo Alto Networks PAN-OS Command Injection"
 
strings:
  $cookie_prefix = "Cookie:"
  $path_traversal = "/../../../"
  $targeted_path = "var/appweb/sslvpndocs/global-protect/portal/images"
 
condition:
  all of (
   $cookie_prefix,
   $path_traversal,
   $targeted_path
  )
}
