package contentfilter

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "amavis"
import "api/basic"

//Update contentfilter(amavis) main setting groups by names via case conditions by url location
func PostHandler(amavisd_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    //Get postfix configuration from file main.cf:
    amavisConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
    mappedAmavisConf := MapMain(amavisConf)
    switch location := ps.ByName("name"); location {
    default:
    jstatus := basic.JsonStatus("Error", "Unknown location")
    http.Error(w, jstatus, http.StatusNotFound)
    case "main":
      //Validate request body:
      newAmavisConf, err := ValidateMain(r.Body, mappedAmavisConf)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in file .cf:
          err = amavis.UpdateConf(amavisConf, newAmavisConf, amavisd_configs_path+"main-amavisd.conf")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
          } else {
                  err = amavis.OsService("reload")
                  if err!=nil{
                    jstatus := basic.RestoreAmavis(amavisd_configs_path, err.Error())
                    http.Error(w, jstatus, http.StatusInternalServerError)
                  } else {
                      jstatus := basic.JsonStatus("Success", "Server configuration updated")
                      fmt.Fprint(w, jstatus)
                    }
                }
              }
    case "release-message":
      //Validate request body:
      id, recipients, err := ValidateReleaseMessage(r.Body)
      numErr := 0
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        numErr = numErr + 1
      } else {
        err = amavis.AmavisdRelease(id, recipients)
        if err !=nil && numErr==0{
          jstatus := basic.JsonStatus("Error", "Error release message: "+err.Error())
          http.Error(w, jstatus, http.StatusInternalServerError)
          } else {
            jstatus := basic.JsonStatus("Success", "Message successfully queued for delivery")
            fmt.Fprint(w, jstatus)
          }
        }
      }

        })
      }
