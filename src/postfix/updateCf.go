package postfix

import ("strconv"
        "io/ioutil"
        "strings")
import ("errors"
        "log")

//Update main.cf configuration map from compiling parameters current and recieved from api
func UpdateMainCf(currentParams map[string][]string,
  inputParams map[string]interface{},
  postfix_configs_path string) error{
    //Mapping config(adding all params):
    var strOk bool
    var err error
    for k := range inputParams{
     arrParam, arrOk := inputParams[k].([]string)
     if arrOk==true{
      currentParams[k] = arrParam
      } else {
      currentParams[k][0], strOk = inputParams[k].(string)
      //If value not string, try handler for int:
      if strOk==false{
        intParam, intOk := inputParams[k].(int)
        //If value not int, generate return error:
        if intOk==false{
          err = errors.New("Convertations to main.cf error: parameter not string and not integer: "+k)
          log.Print(err)
          return err
        }
        //Else convert int to string and map to params:
        currentParams[k][0] = strconv.Itoa(intParam)
      }
     }
    }
    err = writeMainCf(currentParams, postfix_configs_path)
    if err!=nil{
      err = errors.New("Writing to main.cf error: "+err.Error())
      log.Print(err)
      return err
    }
    //If conf files success writed, run reload server process:
    err = osService("reload")
    if err!=nil{
      err = errors.New("Error reload mailserver: "+err.Error())
    }
    return err
}

//Write configuration map to main.cf file
func writeMainCf(mapParams map[string][]string, mainPath string)  error{
  //Convert config to main.cf format:
  var cfString string
  for key := range mapParams{
      cfString = cfString+key+" = "
      if len(mapParams[key])>1{
        values:= strings.Join(mapParams[key], ",")
        cfString = cfString+values+"\n"
      } else {
        cfString = cfString+mapParams[key][0]+"\n"
      }
  }
  //Write config to file:
  err:= ioutil.WriteFile(mainPath, []byte(cfString), 0644)
  if err!=nil{
    log.Print(err)
  }
  return err
}
