package acl

import ("encoding/json"
        "io")
import "regexp"
import "errors"
import "sort"
import "gopkg.in/validator.v2"
import "github.com/gijsbers/go-pcre"

//Init server rules format
type ruleElement struct{
  Subject string
  Action string
  Priority int
}
//Check incoming parameters from json request and generate regexp lookup table string for postfix.
//Lookup table sorting by Priority from request.
func ValidateRegexpTable(inputParams io.Reader, location string) (string, error) {
  //var inputMap map[string][]interface{}
  type inputMapStruct struct{
    Rules []ruleElement
  }
  var inputMap inputMapStruct
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err := decoder.Decode(&inputMap)
  if err !=nil{
    return "", err
  }
  sort.Slice(inputMap.Rules, func(i, j int) bool { return inputMap.Rules[i].Priority< inputMap.Rules[j].Priority })
  //Validate table parameters:
  var reValue, reError string
  switch location {
  case "helo":
      reValue = "^(OK|REJECT).*$"
      reError = "ACL supported only REJECT or OK actions: "
    default:
      return "", errors.New("Unknown regexp table type")
  }
  re := regexp.MustCompile(reValue)
  var result string
  for key:= range inputMap.Rules{
    //Check regexp validate errors:
    ok := re.MatchString(inputMap.Rules[key].Action)
    if !ok{
      return "", errors.New(reError+inputMap.Rules[key].Subject+"  "+inputMap.Rules[key].Action)
    }
    //If checks success, append elements to result string:
    resultSubjectRegexp := "/"+inputMap.Rules[key].Subject+"/"
    result = result+resultSubjectRegexp+"  "+inputMap.Rules[key].Action+"\n"
  }

    return result, err

}

//Init smta ACL data format
type aclEntryStruct struct{
  Rule string
  Action string
  Priority int
}
type aclStruct struct{
  Acl map[string][]aclEntryStruct
}

/*
  Validate parameters and create map adapted for postfix and amavis
  Rewrite STRONG, WHITELIST etc...
*/
func ValidateACL(inputParams io.Reader, location string) (map[string]map[string]map[string]string, error) {
  var subjects aclStruct
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err := decoder.Decode(&subjects)
  if err != nil{
    return nil, err
  }
  //Check input ACL by subject(email or ip)
  for subject := range subjects.Acl{
    err = validateRules(subjects.Acl[subject], location)
    if err != nil{
      return nil, err
    }
  }
  serverRules := newServerRules(subjects.Acl, location)
  return serverRules, err
}

//Check input acl rules and actions
func validateRules(rules []aclEntryStruct, location string) error{
  expressionMap := map[string]map[string][]string{"clients":
        { "client_restrictions": {`^(OK|REJECT)$`, " allowed only OK or REJECT actions in context "},
          "sender_restrictions": {`^(OK)$`, " allowed only OK action in context "} },
      "senders":
        { "client_restrictions": {`^(OK)$`, " allowed only OK action in context "},
          "sender_restrictions": {`^(OK|REJECT)$`, " allowed only OK or REJECT actions in context "},
          "recipient_restrictions": {`^(OK)$`, " allowed only OK action in context "},
          "data_restrictions": {`^(LIGHT)$`, " allowed only LIGHT action in context "},
          "whitelist_sender_restrictions": {`^(OK)$`, " allowed only OK action in context "} },
      "recipients":
        { "sender_restrictions": {`^(REJECT|STRONG|WHITELIST)$`, " allowed only REJECT, STRONG or WHITELIST actions in context "},
          "recipient_restrictions": {`^(STRONG)$`, " allowed only STRONG action in context "},
          "data_restrictions": {`^(STRONG)$`, " allowed only STRONG action in context "},
          "banned_filename_maps_trusted": {`^(BLOCK_ALL|BYPASS_ENCRYPTED)$`, " allowed only BLOCK_ALL or BYPASS_ENCRYPTED actions in context "},
          "banned_filename_maps_origin": {`^(BLOCK_ALL|BYPASS_ENCRYPTED)$`, " allowed only BLOCK_ALL or BYPASS_ENCRYPTED actions in context "} }}

  for i := range rules{
    //Check allowed rules
    rule := rules[i].Rule
    validRule := false
    for allowedRule:= range expressionMap[location]{
      if !validRule { if rule == allowedRule { validRule = true }}
    }
    if !validRule{
      return errors.New("For "+location+" not allowed rule: "+rule)
    } else {
      //Check allowed actions
      expression := expressionMap[location][rule][0]
      re := regexp.MustCompile(expression)
      ok := re.MatchString(rules[i].Action)
      if !ok{
        expressionErr := expressionMap[location][rule][1]
        return errors.New("For "+location+expressionErr+rule+", your action: "+rules[i].Action)
      }
    }
  }
  return nil
}

//Create configuration acl`s adapted for postfix and amavis servers from "smta acl"
func newServerRules(subjects map[string][]aclEntryStruct, location string)  map[string]map[string]map[string]string{
  var tableElement ruleElement
  //Postfix part
  postfixTables := map[string]map[string]string{"clients":
        {"client_restrictions": "", "sender_restrictions": ""},
      "senders":
        {"client_restrictions": "", "sender_restrictions": "", "recipient_restrictions": "", "data_restrictions": "",
          "whitelist_sender_restrictions": ""},
      "recipients":
        {"sender_restrictions": "", "recipient_restrictions": "", "data_restrictions": "" }}
  postfixActions := map[string][]map[string]string{"data_restrictions": {{"STRONG": `FILTER smtp-amavis:[127.0.0.1]:10029`},
                                                                          {"LIGHT": `FILTER smtp-amavis:[127.0.0.1]:10028`}},
                                                    "sender_restrictions": {{"STRONG": `strong_check_sender_restrictions`}, {"WHITELIST": `whitelist_sender_restrictions`}},
                                                    "recipient_restrictions": {{"STRONG": `strong_check_recipient_restrictions`}}}
  postfixRules := make(map[string][]ruleElement)
  for table := range postfixTables[location]{
    for subject := range subjects { for rule := range subjects[subject] {
        if subjects[subject][rule].Rule == table {
          ruleAction := subjects[subject][rule].Action
          if ruleAction != "OK" && ruleAction != "REJECT"{
            for i := range postfixActions[table]{
              for action := range postfixActions[table][i] {
                if ruleAction == action { ruleAction = postfixActions[table][i][action] }
              }
            }
          }
          tableElement.Subject = subject
          tableElement.Action = ruleAction
          tableElement.Priority = subjects[subject][rule].Priority
          postfixRules[table] = append(postfixRules[table], tableElement)
        }
      }}
    /* Sort by priority and create postfix lookup table by example:
       /sexampleUser@example.lan/  OK
    */
    sort.Slice(postfixRules[table], func(i, j int) bool { return postfixRules[table][i].Priority< postfixRules[table][j].Priority })
    var postfixLookupTable string
    for rule := range postfixRules[table]{
      postfixLookupTable = postfixLookupTable+"/"+postfixRules[table][rule].Subject+"/  "+postfixRules[table][rule].Action+"\n"
    }
    postfixTables[location][table] = postfixLookupTable
  }

  //Amavis part
  amavisTables := map[string]map[string]string{"clients":{},"senders":{},
    "recipients":
        {"banned_filename_maps_trusted": "", "banned_filename_maps_origin": ""}}
  amavisRules := make(map[string][]ruleElement)
  for table := range amavisTables[location]{
    for subject := range subjects { for rule := range subjects[subject] {
        if subjects[subject][rule].Rule == table {
          ruleAction := subjects[subject][rule].Action
          tableElement.Subject = subject
          tableElement.Action = ruleAction
          tableElement.Priority = subjects[subject][rule].Priority
          amavisRules[table] = append(amavisRules[table], tableElement)
        }
      }}
    /* Sort by priority and create amavis hash by example:
      [new_RE( [qr'^sexampleUser@example.lan' => 'BYPASS_ENCRYPTED'],  [qr'^.*$' => 'DEFAULT'] )];
    */
    sort.Slice(amavisRules[table], func(i, j int) bool { return amavisRules[table][i].Priority< amavisRules[table][j].Priority })
    ArrayHashRegexpAmavis := `[new_RE( `
    for rule := range amavisRules[table]{
      ArrayHashRegexpAmavis = ArrayHashRegexpAmavis+`[qr'`+amavisRules[table][rule].Subject+`' => '`+amavisRules[table][rule].Action+`'],  `
    }
    ArrayHashRegexpAmavis = ArrayHashRegexpAmavis+`[qr'^.*$' => 'DEFAULT'] )];`
    amavisTables[location][table] = ArrayHashRegexpAmavis
  }
  //Build and return
  aclTables := map[string]map[string]map[string]string{"postfix":{}, "amavis": {}}
  aclTables["postfix"] = postfixTables
  aclTables["amavis"] = amavisTables
  return aclTables
}

/*Check incoming map name
and return extracted map name string from incoming json*/
func ValidateACLReload(inputParams io.Reader) (string, error){
    type mainParams struct {
      Name string `validate:"min=1, regexp=^(helo|recipients|senders|clients|score-maps)$"`
    }
    var tmpParams mainParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err := decoder.Decode(&tmpParams)
    if err !=nil{
      return "", err
    }
    //Validate parameters from json:
    err = validator.Validate(tmpParams)
    if err !=nil{
      return "", errors.New("Reload supported only this ACL types: helo,recipients,senders,clients,score-maps")
    }

    return tmpParams.Name, err
}

/*
  Validate parameters and create amavis $recipient_score_sender_maps
*/
func ValidateScoreMaps(inputParams io.Reader) (string, error) {
  type rule struct{
    Sender string
    Scores string
    Priority int
  }
  type scoreRecipientStruct struct{
    Recipient string
    Priority int
    Senders []rule
  }
  type scoreMapsStruct struct{
    Maps []scoreRecipientStruct
  }
  var subjects scoreMapsStruct
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err := decoder.Decode(&subjects)
  if err != nil{
    return "", err
  }

  //Check input rules by subject (pcre as subject), and create map string
  result := `{`
  //Sort recipients by priority
  sort.Slice(subjects.Maps, func(i, j int) bool {
    return subjects.Maps[i].Priority < subjects.Maps[j].Priority
  })
  //Subject this is recipient map index
  for subject := range subjects.Maps{
    //Validate recipient pcre
    _, err := pcre.Compile(subjects.Maps[subject].Recipient, 0)
    if err != nil {
      err = errors.New("Invalid recipient pcre expression: "+err.Error())
      return "", err
    }
    //Sort senders(in recipient) by priority
    sort.Slice(subjects.Maps[subject].Senders, func(i, j int) bool {
      return subjects.Maps[subject].Senders[i].Priority < subjects.Maps[subject].Senders[j].Priority
    })
    //Init result string
    result = result+` new_RE(qr'`+subjects.Maps[subject].Recipient+`')  =>  `
    rules := `[new_RE(`
    for rule := range subjects.Maps[subject].Senders{
      //Check empty parameters
      if (subjects.Maps[subject].Senders[rule].Sender == "" || subjects.Maps[subject].Senders[rule].Scores == "") {
        err = errors.New("Sender or Scores empty for: "+subjects.Maps[subject].Recipient)
        return "", err
      }
      //Validate scores
      expression := `^(\d\d|\-\d\d|\+\d\d)$`
      re := regexp.MustCompile(expression)
      validScores := re.MatchString(subjects.Maps[subject].Senders[rule].Scores)
      if !validScores {
        err = errors.New("Invalid Scores value for: "+subjects.Maps[subject].Recipient+", score examples: +15,-10,5")
        return "", err
      }
      //Validate sender pcre
      _, err := pcre.Compile(subjects.Maps[subject].Senders[rule].Sender, 0)
      if err != nil {
        err = errors.New("Invalid sender pcre expression: "+err.Error())
        return "", err
      }
      //[qr'.*dx.lan' => +15],
      rules = rules+` [qr'`+subjects.Maps[subject].Senders[rule].Sender+`' => `+subjects.Maps[subject].Senders[rule].Scores+`], `
    }
    rules = rules+`)],`
    result = result+rules
  }
  result = result+` };`
  return result, err
}
