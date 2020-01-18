package acl

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import ("postfix"
        "amavis")
import "api/basic"

//Update acl table groups by names via case conditions by url location
func PostHandler(postfix_configs_path, amavisd_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    switch location := ps.ByName("name"); location {
    case "helo":
      //Validate request body:
      validatedData, err := ValidateRegexpTable(r.Body, "helo")
      if err !=nil{
        jstatus := basic.JsonStatus("Error", err.Error())
        http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          //Mapping and write body in regexp table file:
          err = postfix.UpdateRegexpTable(validatedData, postfix_configs_path+"acl/helo/available/helo_access")
          if err!=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusInternalServerError)
            } else {
                jstatus := basic.JsonStatus("Success", "Server configuration updated")
                fmt.Fprint(w, jstatus)
              }
        }
      case "clients","senders","recipients":
        numErr:=0
        aclTables, err := ValidateACL(r.Body, location)
        if err!=nil && numErr==0{
            numErr = numErr+1
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusBadRequest)
          } else {
            for table := range aclTables["postfix"][location]{
                  if err==nil {
                    err = postfix.UpdateRegexpTable(aclTables["postfix"][location][table], postfix_configs_path+"acl/"+location+"/available/"+table)
                  }
                }
            if err!=nil && numErr==0{
                numErr = numErr+1
                jstatus := basic.JsonStatus("Error", err.Error())
                http.Error(w, jstatus, http.StatusInternalServerError)
              } else {
            //Amavis handle
            newAmavisdConf := make(map[string]string)
            amavisNeedUpdate := false
            for table := range aclTables["amavis"][location]{
              if aclTables["amavis"][location][table] != "" {
                amavisNeedUpdate = true
                newAmavisdConf["my $"+table] = aclTables["amavis"][location][table]
              }
            }
            if amavisNeedUpdate{
              amavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf.available")
              err = amavis.UpdateConf(amavisdConf, newAmavisdConf, amavisd_configs_path+"main-amavisd.conf.available")
            }
            if err!=nil && numErr==0{
                numErr = numErr+1
                jstatus := basic.JsonStatus("Error", err.Error())
                http.Error(w, jstatus, http.StatusInternalServerError)
              } else {
                  jstatus := basic.JsonStatus("Success", "Server configuration updated")
                  fmt.Fprint(w, jstatus)
                }
            }
          }
      case "reload":
        //Validate request body:
        name, err := ValidateACLReload(r.Body)
        if err !=nil{
            jstatus := basic.JsonStatus("Error", err.Error())
            http.Error(w, jstatus, http.StatusBadRequest)
            } else {
                var tablelist []string
                numErr:=0
                switch name {
                default:
                  tablelist = []string{name}
                case "recipients":
                  tablelist = []string{"data_restrictions", "recipient_restrictions", "sender_restrictions"}
                  //Reload amavis service
                  amavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
                  newAmavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf.available")
                  err = amavis.UpdateConf(amavisdConf, newAmavisdConf, amavisd_configs_path+"main-amavisd.conf")
                  if err!=nil && numErr==0{
                      numErr = numErr+1
                      jstatus := basic.JsonStatus("Error", err.Error())
                      http.Error(w, jstatus, http.StatusInternalServerError)
                    } else {
                        err = amavis.OsService("reload")
                        if err!=nil{
                          numErr = numErr+1
                          jstatus := basic.RestoreAmavis(amavisd_configs_path, err.Error())
                          http.Error(w, jstatus, http.StatusInternalServerError)
                        }
                      }
                case "senders":
                  tablelist = []string{"data_restrictions", "recipient_restrictions", "sender_restrictions", "client_restrictions", "whitelist_sender_restrictions"}
                case "clients":
                  tablelist = []string{"sender_restrictions", "client_restrictions"}
                case "score-maps":
                  //Reload amavis service
                  amavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
                  newAmavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf.available")
                  err = amavis.UpdateConf(amavisdConf, newAmavisdConf, amavisd_configs_path+"main-amavisd.conf")
                  if err!=nil && numErr==0{
                      numErr = numErr+1
                      jstatus := basic.JsonStatus("Error", err.Error())
                      http.Error(w, jstatus, http.StatusInternalServerError)
                    } else {
                        err = amavis.OsService("reload")
                        if err!=nil{
                          numErr = numErr+1
                          jstatus := basic.RestoreAmavis(amavisd_configs_path, err.Error())
                          http.Error(w, jstatus, http.StatusInternalServerError)
                        }
                      }
                }
                for table := range tablelist{
                  err = postfix.ApplyTable(tablelist[table], postfix_configs_path+"acl/"+name+"/")
                  if err!=nil && numErr==0{
                    numErr = numErr+1
                    jstatus := basic.JsonStatus("Error", err.Error())
                    http.Error(w, jstatus, http.StatusInternalServerError)
                    }
                  }
                  if numErr == 0 {
                     jstatus := basic.JsonStatus("Success", "New server configuration has been applied")
                     fmt.Fprint(w, jstatus)
                   }
             }
    case "score-maps":
      scoreString, err := ValidateScoreMaps(r.Body)
      if err!=nil {
          jstatus := basic.JsonStatus("Error", err.Error())
          http.Error(w, jstatus, http.StatusBadRequest)
        } else {
          newAmavisdConf := map[string]string{"my $recipient_score_sender_maps": scoreString}
          amavisdConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf.available")
          err = amavis.UpdateConf(amavisdConf, newAmavisdConf, amavisd_configs_path+"main-amavisd.conf.available")
          if err!=nil {
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
