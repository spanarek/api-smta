//Package for managements postfix transport settings
package transport

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "postfix"
import "api/basic"

//Get setting groups by names, via case conditions by url location
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
    case "ldap":
      postfixConfig = postfix.GetMainCf(postfix_configs_path+"mapping/enabled/ldap_alias_maps.cf")
      //Mapping only general data from postfix configs:
      mappedData := MapLdap(postfixConfig)
      //Return
      fmt.Fprint(w, mappedData)
    case "ldap-state":
      //Mapping only general data from postfix configs:
      mappedData := MapLdapState(postfixConfig)
      //Return
      fmt.Fprint(w, mappedData)
    case "map":
      //Get postfix configuration from map table:
      postfixTable, err := postfix.GetRegexpTable(postfix_configs_path+"mapping/enabled/transport_maps")
      if err != nil{
        jstatus := basic.JsonStatus("Error", "Error getting mailserver transport table")
        http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        //Mapping only general data from postfix configs:
        mappedData := MapRegexpTable(postfixTable)
        //Return
        fmt.Fprint(w, mappedData)
      }
    case "map-test":
      email := r.FormValue("email")
      mapType := r.FormValue("type")
      //Validate parameters existing:
      if len(email) == 0 || len(mapType) == 0 {
          jstatus := basic.JsonStatus("Error", "Empty email or type parameters")
          http.Error(w, jstatus, http.StatusBadRequest)
          } else {
              //Validate types from request:
              mapTypes := []string{"ldap", "map", "recipient-bcc", "sender-bcc"}
              validType := false
              for _, a := range mapTypes { if a == mapType { validType = true } }
              if !validType{
                jstatus := basic.JsonStatus("Error", "Map testing supported only this map types: ldap,map,recipient-bcc,sender-bcc")
                http.Error(w, jstatus, http.StatusBadRequest)
                } else {
                    result, err := postfix.PostmapQuery(postfix_configs_path, mapType, email)
                    if err != nil{
                      jstatus := basic.JsonStatus("Error", "Error checking lookup table: "+err.Error())
                      http.Error(w, jstatus, http.StatusInternalServerError)
                      } else {
                        jstatus := basic.JsonStatus("Success", result)
                        fmt.Fprint(w, jstatus) 
                        }
                    }
                  }
    case "recipient-bcc":
      //Get postfix configuration from map table:
      postfixTable, err := postfix.GetRegexpTable(postfix_configs_path+"mapping/enabled/recipient_bcc_maps")
      if err != nil{
        jstatus := basic.JsonStatus("Error", "Error getting mailserver transport table")
        http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        //Mapping only general data from postfix configs:
        mappedData := MapRegexpTable(postfixTable)
        //Return
        fmt.Fprint(w, mappedData)
      }
    case "sender-bcc":
      //Get postfix configuration from map table:
      postfixTable, err := postfix.GetRegexpTable(postfix_configs_path+"mapping/enabled/sender_bcc_maps")
      if err != nil{
        jstatus := basic.JsonStatus("Error", "Error getting mailserver transport table")
        http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        //Mapping only general data from postfix configs:
        mappedData := MapRegexpTable(postfixTable)
        //Return
        fmt.Fprint(w, mappedData)
      }
    }
  })
}
