//Working with postfix mail server
package postfix

import ("io/ioutil"
        "log"
        "strings")

/*This function getting and return parameters map from main.cf format file (key = value1,value2,valueN..),
from postfix configuration folder.
Example map:
 map[smtpd_tls_key_file:[/etc/postfix/ssl/mta01.uniq2Example.lan.key] setgid_group:[postdrop] manpage_directory:[/usr/share/man] readme_directory:[/usr/share/doc/postfix-2.10.1/README_FILES] smtpd_helo_restrictions:[permit_mynetworks  check_helo_access hash:/etc/postfix/wb/helo_access permit_sasl_authenticated reject_non_fqdn_helo_hostname reject_invalid_helo_hostname reject_unknown_helo_hostname] ....*/
func GetMainCf(filepath string) map[string][]string{
  //Reading file from filepath to buffer:
  content, err := ioutil.ReadFile(filepath)
  if err != nil {
    log.Fatal(err)
  }
  //Split buffer in array by newlines:
  lines := strings.Split(string(content), "\n")
  //Create map for all configuration:
  var maincf map[string][]string
  maincf = make(map[string][]string)
  //Check line by line from array lines:
  for line := range lines {
    /*If exist "=", split this line, example:
         smtpd_relay_restrictions = permit_mynetworks, .....*/
    if strings.Contains(lines[line], " = ") {
      values := strings.Split(lines[line], " = ")
      /* If multiplie values in variable, split this value, example:
           smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination, */
      if strings.Contains(values[1], ","){
        keys := strings.Split(string(values[1]), ",")
        maincf[values[0]] = keys
      } else {
        //If one value for variable:
        maincf[values[0]] = append(maincf[values[0]], values[1])
      }
    }
  }
  return maincf
}
