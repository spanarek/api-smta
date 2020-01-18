//Package for managements postfix general(global) settings
package general

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "postfix"
import "api/basic"

//Get setting groups by names via case conditions by url location
func GetHandler(postfix_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    //Get postfix configuration from file main.cf:
    postfixConfig := postfix.GetMainCf(postfix_configs_path+"main.cf")
    switch location := ps.ByName("name"); location {
    default:
      jstatus := basic.JsonStatus("Error", "Unknown location")
      http.Error(w, jstatus, http.StatusNotFound)
    case "main":
      //Mapping only general data from postfix configs:
      mappedData := MapMain(postfixConfig)
      //Return
      fmt.Fprint(w, mappedData)
    case "ssl":
      //Mapping only ssl data from postfix configs:
      mappedData := MapSSL(postfixConfig)
      //Return
      fmt.Fprint(w, mappedData)
    case "cert":
      w.Header().Set("Content-Type", "text/plain")
      cert, err := postfix.GetCert()
      if err !=nil {
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusInternalServerError)
      }
      fmt.Fprint(w, cert)
    }
  })
}
