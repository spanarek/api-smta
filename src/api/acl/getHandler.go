//Package for managements postfix transport settings
package acl

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "fmt")
import ("postfix"
        "amavis")
import "api/basic"

//Get acl groups by names, via case conditions by url location
func GetHandler(postfix_configs_path, amavisd_configs_path string) httprouter.Handle {
  return (func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    w.Header().Set("Content-Type", "application/json")
    aclTables := map[string]map[string]map[string]interface{}{"clients":{}, "senders": {}, "recipients":{}}
    postfixTables := map[string]map[string]map[string]interface{}{"clients":
          {"client_restrictions": {}, "sender_restrictions": {}},
        "senders":
          {"client_restrictions": {}, "data_restrictions": {}, "recipient_restrictions": {}, "sender_restrictions": {}, "whitelist_sender_restrictions": {}},
        "recipients":
          {"data_restrictions": {}, "recipient_restrictions": {}, "sender_restrictions": {}}}
    amavisTables := map[string]map[string]map[string]interface{}{"recipients":
              {"banned_filename_maps_trusted": {}, "banned_filename_maps_origin": {}}}
    switch location := ps.ByName("name"); location {
    default:
      jstatus := basic.JsonStatus("Error", "Unknown location")
      http.Error(w, jstatus, http.StatusNotFound)
    case "helo":
      //Get postfix configuration from map table:
      postfixTable, err := postfix.GetRegexpTable(postfix_configs_path+"acl/helo/enabled/helo_access")
      if err != nil{
        jstatus := basic.JsonStatus("Error", "Error getting mailserver lookup table")
        http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        //Mapping regexp table for api format
        mappedData := MapRegexpTable(postfixTable)
        //Return
        fmt.Fprint(w, mappedData)
        }
    case "clients","senders","recipients":
      numErr:=0
      //Get all tables from postfix by case
      for table := range postfixTables[location]{
        postfixTable, err := postfix.GetRegexpTable(postfix_configs_path+"acl/"+location+"/enabled/"+table)
        if err!=nil && numErr==0{
          numErr = numErr+1
          jstatus := basic.JsonStatus("Error", "Error getting mailserver lookup table: "+table)
          http.Error(w, jstatus, http.StatusInternalServerError)
          }
          postfixTables[location][table] = postfixTable
      }
      aclTables[location] = postfixTables[location]

      /*
      Amavis tables geting from main-amavisd.conf
      For usability config used variables: my $table_name
      Example:
        my $banned_filename_maps_trusted = [{'.' => 'DEFAULT', 'admin@example.lan' => 'BYPASS_ENCRYPTED'}];
      */
      amavisConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
      for table := range amavisTables[location]{
        amavisTable, err := MapArrayHashRegexpAmavis(amavisConf[`my $`+table])
        if err != nil && numErr==0{
          numErr = numErr+1
          jstatus := basic.JsonStatus("Error", "Error getting mailserver lookup table: "+table+": "+err.Error())
          http.Error(w, jstatus, http.StatusInternalServerError)
        }
        aclTables[location][table] = amavisTable
      }

      if numErr==0 {
        mappedData := MapACL(aclTables[location])
        fmt.Fprint(w, mappedData+"\n")
      }
    case "test":
      address := r.FormValue("address")
      tableType := r.FormValue("listType")
      tableTypes := []string{"clients", "senders", "recipients"}
      numErr := 0
      //Validate parameters
      if len(address) == 0 || len(tableType) == 0 {
          jstatus := basic.JsonStatus("Error", "Empty address or listType")
          http.Error(w, jstatus, http.StatusBadRequest)
          numErr = numErr+1
          } else {
            allowed := false
            for i := range tableTypes{  if tableTypes[i] == tableType {  allowed = true }  }
            if !allowed && numErr==0 {
              jstatus := basic.JsonStatus("Error", "listType is unsupported")
              http.Error(w, jstatus, http.StatusBadRequest)
            } else {
                //Check address for all tables postfix
                for table := range postfixTables[tableType]{
                  result, _ := postfix.PostmapQuery(postfix_configs_path+"acl/"+tableType+"/available/"+table, tableType, address)
                  postfixTables[tableType][table] = map[string]interface{}{"action": result}
                }
                aclTables[tableType] = postfixTables[tableType]
                fmt.Fprint(w, MapACLTest(aclTables[tableType]))
              }
            }
    case "smart-test":
      from := r.FormValue("from")
      to := r.FormValue("to")
      numErr := 0
      if len(from) == 0 || len(to) == 0 {
          jstatus := basic.JsonStatus("Error", "Empty \"from\" or \"to\" addresses")
          http.Error(w, jstatus, http.StatusBadRequest)
          numErr = numErr+1
          } else {
            success := false
            //Check existing recipient in my relay domains
            postfixConfig := postfix.GetMainCf(postfix_configs_path+"main.cf")
            relay_domains := postfixConfig["relay_domains"]
            var mydomain bool
            mydomain = CheckRelayDomain(relay_domains, to)
            if !mydomain {
              success = true
              fmt.Fprint(w, basic.SmartTestJsonStatus("Discarded", "Unrelated domain"))
            }
            //Get postfix rules for sender
            if !success{
            for table := range postfixTables["senders"]{
              result, _ := postfix.PostmapQuery(postfix_configs_path+"acl/senders/available/"+table, "senders", from)
              if result == "REJECT" {
                success = true
                fmt.Fprint(w, basic.SmartTestJsonStatus("Discarded", "Sender is blocked for all recipients"))
              }
              postfixTables["senders"][table] = map[string]interface{}{"action": result}
            }}
            //If sender don`t banned
            if !success{
              //Get postfix rules for recipient
             for table := range postfixTables["recipients"]{
               result, _ := postfix.PostmapQuery(postfix_configs_path+"acl/recipients/available/"+table, "recipients", to)
               if result == "REJECT" {
                 success = true
                 fmt.Fprint(w, basic.SmartTestJsonStatus("Discarded", "Recipient is blocked for all senders"))
               }
               //Check whitelist_senders_only rule
               if result == "whitelist_sender_restrictions\n"{
                 if postfixTables["senders"]["whitelist_sender_restrictions"]["action"].(string) != "OK\n"{
                   fmt.Fprint(w, basic.SmartTestJsonStatus("Blacklisted", "Sender is not allowed for this recipient"))
                   success = true
                 }
               }
               postfixTables["recipients"][table] = map[string]interface{}{"action": result}
             }
            }
            //If recipient don`t banned in postfix
            if !success{
              //Get amavis rules
              //Get amavis score maps
                amavisConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf.available")
                amavisScoreMaps, err := MapRecipientScoreSenderAmavis(amavisConf[`my $recipient_score_sender_maps`])
                if err != nil && numErr==0{
                  jstatus := basic.JsonStatus("Error", "Error getting score maps: "+err.Error())
                  http.Error(w, jstatus, http.StatusInternalServerError)
                } else {
                  for amavisTableName := range amavisTables["recipients"]{
                    amavisTable, err := MapArrayHashRegexpAmavis(amavisConf[`my $`+amavisTableName])
                    if err != nil && numErr==0{
                      numErr = numErr+1
                      jstatus := basic.JsonStatus("Error", "Error getting mailserver lookup table: "+amavisTableName+": "+err.Error())
                      http.Error(w, jstatus, http.StatusInternalServerError)
                    }
                    amavisTables["recipients"][amavisTableName] = amavisTable
                  }
                  result, err := SmartTestAmavis(from, to, postfixTables, amavisTables, amavisScoreMaps, amavisConf)
                  if err != nil && numErr==0{
                    jstatus := basic.JsonStatus("Error", "Error smart analysis: "+err.Error())
                    http.Error(w, jstatus, http.StatusInternalServerError)
                  } else {
                    fmt.Fprint(w, result)
                  }
                }
            }
          }
    case "score-maps":
      amavisConf := amavis.GetAmavisdConf(amavisd_configs_path+"main-amavisd.conf")
      amavisTable, err := MapRecipientScoreSenderAmavis(amavisConf[`my $recipient_score_sender_maps`])
      if err != nil{
        jstatus := basic.JsonStatus("Error", "Error getting score maps: "+err.Error())
        http.Error(w, jstatus, http.StatusInternalServerError)
      } else {
        fmt.Fprint(w, MapScoreMaps(amavisTable))
      }
    }
  })
}
