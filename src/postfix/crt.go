package postfix

import ("io/ioutil")
import ("log"
        "errors")

//Get certificate file content
func GetCert() (string, error){
  var PATH = "/etc/ssl/certs/postfix.crt"
  content, err := ioutil.ReadFile(PATH)
  if err!=nil{
    err = errors.New("Error reading certificate file: "+err.Error())
    log.Print(err)
    return "", err
  }
  return string(content), err
}

//Update certificate and key files and restart postfix server
func UpdateCert(cert, key string)  error {
  var err error
  err = ioutil.WriteFile("/etc/ssl/certs/postfix.crt", []byte(cert), 0640)
  if err!=nil{
    err = errors.New("Error writing certificate file: "+err.Error())
    log.Print(err)
    return err
  }
  err = ioutil.WriteFile("/etc/ssl/private/postfix.key", []byte(key), 0640)
  if err!=nil{
    err = errors.New("Error writing key file: "+err.Error())
    log.Print(err)
    return err
  }
  //If certificate files success writed, run restart server process:
  err = osService("restart")
  if err!=nil{
    err = errors.New("Error restart mailserver: "+err.Error())
  }
  return err
  }
