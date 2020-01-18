package general

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "postfix"
import "api/basic"

//Update setting groups by names, via case conditions by url location
func PostHandler(postfix_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    switch location := ps.ByName("name"); location {
    default:
      //Get postfix configuration from file main.cf:
      postfixConfig := postfix.GetMainCf(postfix_configs_path+"main.cf")
      //Validate request body:
      validatedData, err := ValidateGeneral(r.Body, location)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in file main.cf:
          err = postfix.UpdateMainCf(postfixConfig, validatedData, postfix_configs_path+"main.cf")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
              }
            }
    case "cert":
      validatedCert, validatedKey, err := ValidateCert(r.Body)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in file main.cf:
          err = postfix.UpdateCert(validatedCert, validatedKey)
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
              }
            }
    }
  })
}
