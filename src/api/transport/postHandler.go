package transport

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import "postfix"
import "api/basic"

//Update transport setting groups by names via case conditions by url location
func PostHandler(postfix_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    //Get postfix configuration from file main.cf:
    postfixConfig := postfix.GetMainCf(postfix_configs_path+"main.cf")
    switch location := ps.ByName("name"); location {
    case "main":
      //Validate request body:
      validatedData, err := ValidateMain(r.Body)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in file .cf:
          err = postfix.UpdateMainCf(postfixConfig, validatedData, postfix_configs_path+"main.cf")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
              }
            }
    case "ldap":
      //Validate request body:
      validatedData, err := ValidateLdap(r.Body)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in file .cf:
          postfixConfig = postfix.GetMainCf(postfix_configs_path+"mapping/enabled/ldap_alias_maps.cf")
          err = postfix.UpdateMainCf(postfixConfig, validatedData, postfix_configs_path+"mapping/available/ldap_alias_maps.cf")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
              jstatus := basic.JsonStatus("Success", "Server configuration updated")
              fmt.Fprint(w, jstatus)
              }
            }
    case "ldap-state":
      //Validate request body:
      enabled, err := ValidateLdapState(r.Body)
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusInternalServerError)
        } else {
            maincf:= make(map[string]interface{})
            switch enabled {
            case false:
              maincf["relay_recipient_maps"] = ""
            case true:
              maincf["relay_recipient_maps"] = postfix_configs_path+"mapping/enabled/ldap_alias_maps.cf"
            }
            err = postfix.UpdateMainCf(postfixConfig, maincf, postfix_configs_path+"main.cf")
            if err!=nil{
              jstatus := basic.JsonStatus("Error", err.Error())
              http.Error(w, jstatus, http.StatusInternalServerError)
              } else {
                  jstatus := basic.JsonStatus("Success", "Server configuration updated")
                  fmt.Fprint(w, jstatus)
                }
        }
    case "map":
      //Validate request body:
      validatedData, err := ValidateRegexpTable(r.Body, "map")
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Maping and write body in regexp table file:
          err = postfix.UpdateRegexpTable(validatedData, postfix_configs_path+"mapping/available/transport_maps")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
              }
        }
      case "map-reload":
        //Validate request body:
        name, err := ValidateMapReload(r.Body)
        if err !=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusBadRequest)
          } else {
            err = postfix.ApplyTable(name, postfix_configs_path+"mapping/")
            if err!=nil{
              jstatus := basic.JsonStatus("Error", err.Error())
              http.Error(w, jstatus, http.StatusInternalServerError)
              } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
                }
          }
      case "recipient-bcc":
        //Validate request body:
        validatedData, err := ValidateRegexpTable(r.Body, "bcc")
        if err !=nil{
          jstatus := basic.JsonStatus("Error", err.Error())
          http.Error(w, jstatus, http.StatusBadRequest)
          } else {
            //Maping and write body in regexp table file:
            err = postfix.UpdateRegexpTable(validatedData, postfix_configs_path+"mapping/available/recipient_bcc_maps")
            if err!=nil{
                jstatus := basic.JsonStatus("Error", err.Error())
                http.Error(w, jstatus, http.StatusInternalServerError)
              } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
                }
          }
        case "sender-bcc":
          //Validate request body:
          validatedData, err := ValidateRegexpTable(r.Body, "bcc")
          if err !=nil{
              jstatus := basic.JsonStatus("Error", err.Error())
              http.Error(w, jstatus, http.StatusBadRequest)
            } else {
              //Maping and write body in regexp table file:
              err = postfix.UpdateRegexpTable(validatedData, postfix_configs_path+"mapping/available/sender_bcc_maps")
              if err!=nil{
                  jstatus := basic.JsonStatus("Error", err.Error())
                  http.Error(w, jstatus, http.StatusInternalServerError)
                } else {
                  jstatus := basic.JsonStatus("Success", "Server configuration updated")
                  fmt.Fprint(w, jstatus)
                  }
            }
    default:
        jstatus := basic.JsonStatus("Error", "Unknown location")
        http.Error(w, jstatus, http.StatusNotFound)
    }
  })
}
