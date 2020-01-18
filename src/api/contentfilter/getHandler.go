package contentfilter

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "amavis"
import "api/basic"

/*Get contentfilter(amavis) setting groups by names via case conditions by url location,
  get quarantine messages info*/
func GetHandler(amavisd_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
  w.Header().Set("Content-Type", "application/json")
  //Get amavis configuration from file main-amavisd.conf:
  amavisConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
  switch location := ps.ByName("name"); location {
  default:
    jstatus := basic.JsonStatus("Error", "Unknown location")
    http.Error(w, jstatus, http.StatusNotFound)
  case "main":
    //Mapping only general data from amavis config:
    mappedData := MapMain(amavisConf)
    //Return
    fmt.Fprint(w, mappedData)
  case "quarantine-list":
    dateStart := r.FormValue("dateStart")
    dateEnd := r.FormValue("dateEnd")
    slimit := r.FormValue("limit")
    rawList, err := amavis.GetMessageList(amavisConf["$QUARANTINEDIR"])
    numErr := 0
    if err != nil{
      numErr = 1
      jstatus := basic.JsonStatus("Error", err.Error())
      http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        mappedData, err := MapQuarantineList(rawList, slimit, dateStart, dateEnd)
        if err != nil || numErr != 0{
          jstatus := basic.JsonStatus("Error", err.Error())
          http.Error(w, jstatus, http.StatusBadRequest)
        } else {
            fmt.Fprint(w, mappedData)
        }
      }
    case "quarantine-message":
      messageId := r.FormValue("id")
      rawHeaders, err := amavis.GetMessageHeaders(messageId, amavisConf["$QUARANTINEDIR"])
      if err != nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusInternalServerError)
        } else {
          fmt.Fprint(w, MapQuarantineMessageHeaders(rawHeaders))
        }
  }
})
}
