//Base functions for all api methods
package basic

import "amavis"

//Create json response status messages from simple string
func JsonStatus(status, msg string) string{
  switch status {
  case "Error":
    return "{\"Error\": \""+msg+"\"}"
  case "Success":
    return "{\"Success\": \""+msg+"\"}"
  default:
    return "{\"Info\": \""+msg+"\"}"
  }
}

//Create json response status messages for smart test result
func SmartTestJsonStatus(verdict, info string)  string{
  return "{\"verdict\": \""+verdict+"\", \"info\": [\""+info+"\"]}"
}

func RestoreAmavis(amavisd_configs_path, err string)  string{
  errMessage := "Error reload contentfilter: "+err+", configuration has been restored"
  //Restore config
  unrestored := amavis.RestoreConf(amavisd_configs_path+"main-amavisd.conf")
  if unrestored!=nil{
    errMessage = errMessage+", configuration is unrestored: "+unrestored.Error()
  }
  //Apply restored config
  unrestarted := amavis.OsService("reload")
  if unrestarted!=nil{
    errMessage = errMessage+", amavisd service crashed: "+unrestarted.Error()
  }

  jstatus := JsonStatus("Error", errMessage)
  return jstatus
}
