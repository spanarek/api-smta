//Working with amavis content filter server
package amavis

import ("io/ioutil"
        "log"
        "strings")
import ("os"
        "sort")
import "net/textproto"
import "bufio"

//Get amavisd configuration parameters as map
func GetAmavisdConf(filepath string) map[string]string{
  //Reading file from filepath to buffer:
  content, err := ioutil.ReadFile(filepath)
  if err != nil {
    log.Fatal(err)
  }
  //Split buffer in array by newlines:
  lines := strings.Split(string(content), "\n")
  //Create map for all configuration:
  amavisd_conf := make(map[string]string)
  //Check line by line from array lines:
  for line := range lines {
    /*If exist "=", split this line, example:
         smtpd_relay_restrictions = permit_mynetworks, .....*/
    if strings.Contains(lines[line], " = ") {
      values := strings.Split(lines[line], " = ")
      amavisd_conf[values[0]] = values[1]
    }
  }
  return amavisd_conf
}

//Get file list from quarantine folder
func GetMessageList(dirPath string) ([]os.FileInfo, error){
  dirPath = strings.TrimPrefix(dirPath, "\"")
  dirPath = strings.TrimRight(dirPath, "\";")
  files, err := ioutil.ReadDir(dirPath)
	if err != nil {
    log.Print(err)
    return nil, err
  }
  sort.Slice(files, func(i,j int) bool{
    return files[i].ModTime().Unix() < files[j].ModTime().Unix()
  })
  return files, err
}

//Get headers from message file
func GetMessageHeaders(id, dirPath string)  (map[string]string, error){
  dirPath = strings.TrimPrefix(dirPath, "\"")
  dirPath = strings.TrimRight(dirPath, "\";")
  fileHandler, err := os.Open(dirPath+"/"+id)
  defer fileHandler.Close()
  result := map[string]string{}
  if err == nil {
    reader := bufio.NewReader(fileHandler)
    tr := textproto.NewReader(reader)
    parse, _ := tr.ReadMIMEHeader()
     result["from"] = parse["From"][0]
     result["to"] = parse["To"][0]
     result["subject"] = parse["Subject"][0] 
   }
  return result, err
}
