package transport

import ("encoding/json"
        "io")
import "github.com/fatih/structs"
import "regexp"
import "errors"
import "sort"
import "gopkg.in/validator.v2"

/*Check incoming "main" group parameters from json request
and generate map array for postfix.UpdateMainCf method*/
func ValidateMain(inputParams io.Reader) (map[string]interface{}, error){
  type mainParams struct {
    Relay_domains []string
    Mynetworks []string
  }
    var tmpParams mainParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err := decoder.Decode(&tmpParams)
    if err !=nil{
      return nil, err
    }
    //Check empty parameters from json:
    if len(tmpParams.Relay_domains)==0||len(tmpParams.Mynetworks)==0{
      return nil, errors.New("Relay_domains and mynetworks is required field")
    }
    //Check domains via regexp:
    for domain:= range tmpParams.Relay_domains{
      currentDomain:= tmpParams.Relay_domains[domain]
      re := regexp.MustCompile("^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}$")
      ok := re.MatchString(currentDomain)
      if !ok{
        return nil, errors.New("Regexp validation failed: It is not domain name: "+currentDomain)
      }
    }
    //Check mynetworks via regexp:
    for network:= range tmpParams.Mynetworks{
      currentNetwork := tmpParams.Mynetworks[network]
      re := regexp.MustCompile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\/[0-9]{1,2}$")
      ok := re.MatchString(currentNetwork)
      if !ok{
        return nil, errors.New("Regexp validation failed: It is not ip network style: "+currentNetwork)
      }
    }
    /*If validate and decoder success:
      Lower field names and convert parameters to map for return:*/
    result := structs.Map(tmpParams)

  return result, err
}

//Check incoming parameters from json request and generate regexp lookup table string for postfix.
//Lookup table sorting by Priority from request.
func ValidateRegexpTable(inputParams io.Reader, location string) (string, error) {
  //var inputMap map[string][]interface{}
  type regexpTableElement struct{
    Src string
    Dst string
    Priority int
  }
  type inputMapStruct struct{
    Map []regexpTableElement
  }
  var inputMap inputMapStruct
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err := decoder.Decode(&inputMap)
  if err !=nil{
    return "", err
  }
  sort.Slice(inputMap.Map, func(i, j int) bool { return inputMap.Map[i].Priority< inputMap.Map[j].Priority })
  //Validate table parameters:
  var reValue, reError string
  switch location {
    case "map":
      reValue = "^(smtp:|local:).*$"
      reError = "Transport supported only smtp or local type for delivery: "
    case "bcc":
      reValue = "^[^\\.].*@.*\\..*.[^\\.]$"
      reError = "Bcc supported only email address for delivery: "
    default:
      return "", errors.New("Unknown regexp table type")
  }
  re := regexp.MustCompile(reValue)
  var result string
  for key:= range inputMap.Map{
    //Check regexp validate errors:
    ok := re.MatchString(inputMap.Map[key].Dst)
    if !ok{
      return "", errors.New(reError+inputMap.Map[key].Dst)
    }
    //Append regexp quotes:
    Src := "/"+inputMap.Map[key].Src+"/"
    //If checks success, append elements to result string:
    result = result+Src+"  "+inputMap.Map[key].Dst+"\n"
  }

    return result, err

}

/*Check incoming "ldap" group parameters from json request
and generate map array for postfix.UpdateMainCf method*/
func ValidateLdap(inputParams io.Reader) (map[string]interface{}, error){
  type mainParams struct {
    Bind string `validate:"regexp=^(yes|no)"`
    //regexp for ldap bind_dn format(email address):
    Bind_dn string `validate:"min=3,max=90,regexp=^[^\\.].*@.*\\..*.[^\\.]$"`
    Bind_pw string `validate:"min=12, max=99"`
    Query_filter string `validate:"min=1, max=999"`
    Result_attribute string `validate:"min=1, max=999"`
    Search_base string `validate:"min=1, max=999"`
    Server_port int `validate:"min=1, max=9999"`
    Timeout int `validate:"min=1, max=9999"`
    Version int `validate:"min=1, max=99"`
    Server_host []string `validate:"min=1"`
  }
  var tmpParams mainParams
  var err error
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err = decoder.Decode(&tmpParams)
  if err !=nil{
    return nil, err
  }
  //Validate parameters from json:
  err = validator.Validate(tmpParams)
  if err !=nil{
    return nil, err
  }
  /*If validate and decoder success:
    Lower field names and convert parameters to map for return:*/
  result := structs.Map(tmpParams)
  return result, err
}
/*Check incoming ldap state parameter
and return bool from incoming json*/
func ValidateLdapState(inputParams io.Reader) (bool, error){
    type mainParams struct {
      Enabled bool
    }
    var tmpParams mainParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err := decoder.Decode(&tmpParams)

    return tmpParams.Enabled, err
}

/*Check incoming map name
and return extracted map name string from incoming json*/
func ValidateMapReload(inputParams io.Reader) (string, error){
    type mainParams struct {
      Name string `validate:"min=1, regexp=^(ldap|map|recipient-bcc|sender-bcc)$"`
    }
    var tmpParams mainParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err := decoder.Decode(&tmpParams)
    if err !=nil{
      return "", err
    }
    //Validate parameters from json:
    err = validator.Validate(tmpParams)
    if err !=nil{
      return "", errors.New("Reload supported only this map types: ldap,map,recipient-bcc,sender-bcc")
    }

    return tmpParams.Name, err
}
