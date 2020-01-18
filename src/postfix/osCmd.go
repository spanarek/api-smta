package postfix

import "os/exec"
import "log"
import "strings"

//Working with postfix service via systemd
func osService(action string) error{
  var err error

  if action == "restart" {
    action = "stop"
    preCmd := exec.Command("sudo", "postfix", action)
    err = preCmd.Run()
    if err!=nil{
      log.Print("Postfix service "+action+" error: "+err.Error())
      return err
    }
    action = "start"
  }

  cmd := exec.Command("sudo", "postfix", action)
  err = cmd.Run()
  if err!=nil{
    log.Print("Postfix service "+action+" error: "+err.Error())
  }

  return err
}

//Working with postmap util
func PostmapQuery(postfix_configs_path, tablename, query string) (string, error){
  var tablefilename, tableformat string
  tableformat = "pcre"
  tablefilename = postfix_configs_path
  switch tablename {
  case "map":
    tablefilename = postfix_configs_path+"mapping/available/transport_maps"
  case "recipient-bcc":
    tablefilename = postfix_configs_path+"mapping/available/recipient_bcc_maps"
  case "sender-bcc":
    tablefilename = postfix_configs_path+"mapping/available/sender_bcc_maps"
  case "ldap":
    tableformat = "ldap"
    tablefilename = postfix_configs_path+"mapping/available/ldap_alias_maps.cf"
  }

  out, err := exec.Command("postmap", "-q", query, tableformat+":"+tablefilename).CombinedOutput()
 
   if string(out) != "" && err != nil {
    log.Print(string(out))
   } else if string(out) == "" {
      return "Rules not found", nil
   } 

  outLine := strings.Replace(string(out), "\n", "", -1)
  return outLine, err
}
