package transport

import  "encoding/json"
import "strconv"

//Mapping main transport data from postfix main.cf
func MapMain(postfixMainCf map[string][]string) string{
  //Create map:
  result := map[string]interface{}{
    "relay_domains": postfixMainCf["relay_domains"],
    "mynetworks": postfixMainCf["mynetworks"],
  }
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(result)
  return string(jsonString)
}

//Mapping postfix regexp lookup tables
func MapRegexpTable(RegexpMap map[string]interface{}) string{
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(RegexpMap)
  return string(jsonString)
}

//Mapping postfix ldap lookup configuration
func MapLdap(postfixMainCf map[string][]string) string{
  server_port, _ := strconv.Atoi(postfixMainCf["server_port"][0])
  version, _ := strconv.Atoi(postfixMainCf["version"][0])
  timeout, _ := strconv.Atoi(postfixMainCf["timeout"][0])

  result := map[string]interface{}{
    "server_host": postfixMainCf["server_host"],
    "server_port": server_port,
    "version": version,
    "timeout": timeout,
    "search_base": postfixMainCf["search_base"][0],
    "query_filter": postfixMainCf["query_filter"][0],
    "result_attribute": postfixMainCf["result_attribute"][0],
    "bind": postfixMainCf["bind"][0],
    "bind_dn": postfixMainCf["bind_dn"][0],
    "bind_pw": "Bind password don`t returned for security",
  }
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(result)
  return string(jsonString)
}

//Create json configuration via converting parameter relay_recipient_maps from main.cf.
//If relay_recipient_maps empty, returning disable status
func MapLdapState(postfixMainCf map[string][]string) string{
  result := make(map[string]interface{})
  if postfixMainCf["relay_recipient_maps"][0] != ""{
    result["enabled"] = true
  } else {
      result["enabled"] = false
  }
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(result)
  return string(jsonString)
}
