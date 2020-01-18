package postfix

import ("io/ioutil"
        "log"
        "strings")
import "github.com/fatih/structs"

/*Getting and return parameters map
from postfix regexp tables*/
func GetRegexpTable(tablepath string) (map[string]interface{}, error){
  //Reading file from path to buffer:
  content, err := ioutil.ReadFile(tablepath)
  if err != nil {
    log.Print(err)
    return nil, err
  }
  //Split buffer in array by newlines:
  lines := strings.Split(string(content), "\n")
  //Create struct for table elements:
  type regexpTableElement struct{
    Src string
    Dst string
    Priority int
  }
  type resultStruct struct{
    Map []regexpTableElement
  }
  var result resultStruct
  //Append struct from line elements:
  result.Map = make([]regexpTableElement, len(lines)-1)
  for line := range lines {
    //Split line by two spaces:
    if strings.Contains(lines[line], "  ") {
      values := strings.Split(lines[line], "  ")
      result.Map[line].Priority = line
      Src := values[0]
      removeRegexpQoutes := strings.NewReplacer("/", "")
      Src = removeRegexpQoutes.Replace(Src)
      result.Map[line].Src = Src
      result.Map[line].Dst = values[1]
    }
  }
  return structs.Map(result), err
}

/*Write lookup regexp table to file in api edited(available) folder*/
func UpdateRegexpTable(inputParams string, tablepath string) error{
  //Write table to file:
  err:= ioutil.WriteFile(tablepath, []byte(inputParams), 0644)
  if err!=nil{
    log.Print(err)
  }
  return err
}

/*Copy lookup table file from api edited(available) in server used(enabled) file*/
func ApplyTable(tablename, tablepath string) error{
  var tablefilename string
  switch tablename {
  default:
    tablefilename = tablename
  case "ldap":
    tablefilename = "ldap_alias_maps.cf"
  case "map":
    tablefilename = "transport_maps"
  case "recipient-bcc":
    tablefilename = "recipient_bcc_maps"
  case "sender-bcc":
    tablefilename = "sender_bcc_maps"
  case "helo":
    tablefilename = "helo_access"
  }
  //Copy table from available to enabled:
  content, err := ioutil.ReadFile(tablepath+"available/"+tablefilename)
  if err != nil {
    log.Print(err)
    return err
  }
  err = ioutil.WriteFile(tablepath+"enabled/"+tablefilename, content, 0644)
  if err!=nil{
    log.Print(err)
    return err
  }
  //Postfix needed reload for read new tables
  err = osService("reload")
  if err !=nil {
    log.Print(err)
  }
  return err
}
