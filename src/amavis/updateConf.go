package amavis
import ("errors"
        "log")
import "io/ioutil"

//Update amavis configuration
func UpdateConf(currentParams, inputParams map[string]string, configs_path string)  error{
  //Rewrite current on input parameters
  for table := range inputParams{
    currentParams[table] = inputParams[table]
  }
  err := backupConf(configs_path)
  if err!=nil{
    err = errors.New("Backup amavisd.conf error: "+err.Error())
    log.Print(err)
    return err
  }
  err = writeConf(currentParams, configs_path)
  if err!=nil{
    err = errors.New("Writing to amavisd.conf error: "+err.Error())
    log.Print(err)
  }
  return err
}

//Write configuration map to amavisd.conf file
func writeConf(mapParams map[string]string, mainPath string)  error{
  //create conf string
  var cfString string
  for key := range mapParams{
      cfString = cfString+key+" = "+mapParams[key]+"\n"
      }
  //Write config to file:
  err:= ioutil.WriteFile(mainPath, []byte(cfString), 0644)
  if err!=nil{
    log.Print(err)
  }
  return err
}

//Backup conf file content
func backupConf(conf_path string) error{
  content, err := ioutil.ReadFile(conf_path)
  if err!=nil{
    err = errors.New("Error reading source file: "+err.Error())
    log.Print(err)
    return err
  }
  //Write main file to backup
  err = ioutil.WriteFile(conf_path+".backup", content, 0640)
  if err!=nil{
    err = errors.New("Error writing backup file: "+err.Error())
    log.Print(err)
  }
  return err
}

//Restore conf file content
func RestoreConf(conf_path string) error{
  content, err := ioutil.ReadFile(conf_path+".backup")
  if err!=nil{
    err = errors.New("Error reading backup file: "+err.Error())
    log.Print(err)
    return err
  }
  //Write backup to main file
  err = ioutil.WriteFile(conf_path, content, 0640)
  if err!=nil{
    err = errors.New("Error writing restored file: "+err.Error())
    log.Print(err)
  }
  return err
}
