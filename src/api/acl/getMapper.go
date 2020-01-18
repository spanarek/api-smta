package acl

import "encoding/json"
import "github.com/fatih/structs"
import "regexp"
import "strings"
import "errors"
import "github.com/gijsbers/go-pcre"
import "strconv"

//Mapping regexp lookup table to acl names format
func MapRegexpTable(RegexpMap map[string]interface{}) string{
  type ruleElement struct{
    Subject string
    Action string
    Priority int
  }
  type resultStruct struct{
    Rules []ruleElement
  }
  var result resultStruct
  inputMap := RegexpMap["map"].([]interface{})
  result.Rules = make([]ruleElement, len(inputMap))
  inputRule := make(map[string]interface{})
  for rule := range inputMap{
    inputRule = inputMap[rule].(map[string]interface{})
    result.Rules[rule].Priority = inputRule["priority"].(int)
    result.Rules[rule].Subject = inputRule["src"].(string)
    result.Rules[rule].Action = inputRule["dst"].(string)
  }
  //Lower field names and convert parameters to map
  resultMap := structs.Map(result)
  //Encode json
  jsonString, _ := json.Marshal(resultMap)
  return string(jsonString)
}

//Mapping multitable map by subject(src or key) in smta acl format
func MapACL(RegexpMaps map[string]map[string]interface{}) string{
  //Init ACL data format
  type aclEntryStruct struct{
    Rule string
    Action string
    Priority int
  }
  type aclStruct struct{
    Acl map[string][]aclEntryStruct
  }
  var subjects aclStruct
  subjects.Acl = make(map[string][]aclEntryStruct)
  var entry aclEntryStruct
  //Convertation regexp map parameters for acl usability
  regexpMap := map[string]string{"^FILTER smtp-amavis:\\[127.0.0.1\\]:10028$": "LIGHT",
                                 "^FILTER smtp-amavis:\\[127.0.0.1\\]:10029$": "STRONG",
                                 "^(strong_check_recipient_restrictions|strong_check_sender_restrictions)$": "STRONG",
                                 "^whitelist_sender_restrictions$": "WHITELIST",
                               }
  //Convert map from table files(multimaps) to one acl by format
  for table := range RegexpMaps{
    for rule := range RegexpMaps[table]{
      ruleMaps := RegexpMaps[table][rule].([]interface{})
      for ruleInterface := range ruleMaps{
        ruleMap := ruleMaps[ruleInterface].(map[string]interface{})
          entry.Rule = table
          entry.Priority = ruleMap["priority"].(int)
          entry.Action = ruleMap["dst"].(string)
          //Rewrite action for usability
          for expression := range regexpMap{
            re := regexp.MustCompile(expression)
            if re.MatchString(entry.Action){
              entry.Action = regexpMap[expression]
            }
          }
          entryKey := ruleMap["src"].(string)
        subjects.Acl[entryKey] = append(subjects.Acl[entryKey], entry)
      }
    }
  }
  //Lower field names and convert parameters to map
  resultMap := structs.Map(subjects)
  //Encode json
  jsonString, _ := json.Marshal(resultMap)
  return string(jsonString)
}

/*
Mapping amavis regexp function(new_RE) and hash type arrays:
  [new_RE( [qr'^sexampleUser@example.lan' => 'BYPASS_ENCRYPTED'],  [qr'^.*$' => 'DEFAULT'] )];
  This hash and regexp format is perl-like
*/
func MapArrayHashRegexpAmavis(hashString string) (map[string]interface{}, error){
  type tableElement struct{
    Src string
    Dst string
    Priority int
  }
  type resultStruct struct{
    Map []tableElement
  }
  var result resultStruct
  var entry tableElement
  amavis_RE := extractAmavisnew_RE(hashString)
  if amavis_RE == ""{
    return nil, errors.New("Error extract amavis regular expressions array")
  }
  hashTable := strings.Split(amavis_RE, ",  ")
  for i := range hashTable{
    if strings.Contains(hashTable[i], " => "){
      rule := strings.Split(hashTable[i], " => ")
      entry.Priority = i
      entry.Src = extractAmavisExpression(rule[0])
      if entry.Src == "" {
        return nil, errors.New("Error extract amavis regular expression for: "+rule[0])
      }
      removeSymbols := strings.NewReplacer("'", "",
                                           "]", "",
                                           "[", "",
                                           " ", "",
                                           ",", "")
      entry.Dst = removeSymbols.Replace(rule[1])
      //Don`t append if entry.Src == .* (it is default rule, writing automatically in end)
      if entry.Src != "^.*$"{
        result.Map = append(result.Map, entry)
      }
    }
  }
  //Lower field names and convert parameters to map
  resultMap := structs.Map(result)
  return resultMap, nil
}

//Extract new_RE function content
func extractAmavisnew_RE(content string) string{
  patterns := []string{`(?m)^\[new_RE\( (?P<result>.*) \)\];$`,
                       `(?m)^\(new_RE\( (?P<result>.*) \)\);$`,
                       `(?m)^\[new_RE\( (?P<result>.*)$`}
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    template := "$result"
    for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
      // Apply the captured submatches to the template and append the output
      // to the result.
      result = pattern.ExpandString(result, template, content, submatches)
    }
  }
  return string(result)
}

//Extract regular expression body
func extractAmavisExpression(content string) string{
  //pattern := regexp.MustCompile(`(?m)^\[qr'(?P<result>.*)'$`)
  patterns := []string{`(?m)^\[qr'(?P<result>.*)'$`,
                       `(?m)^ new_RE\(qr'(?P<result>.*)'\)$`,
                       `(?m)^new_RE\(qr'(?P<result>.*)'\)$`,
                       `(?m)^'(?P<result>.*)'$`}
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    template := "$result"
    for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
      // Apply the captured submatches to the template and append the output
      // to the result.
      result = pattern.ExpandString(result, template, content, submatches)
    }
  }
  return string(result)

}

//Mapping test requests
func MapACLTest(inputMap map[string]map[string]interface{}) string{
  regexpMap := map[string]string{"^(FILTER smtp-amavis:\\[127.0.0.1\\]:10028)$": "LIGHT",
                                 "^(FILTER smtp-amavis:\\[127.0.0.1\\]:10028\n)$": "LIGHT",
                                 "^(FILTER smtp-amavis:\\[127.0.0.1\\]:10029)$": "STRONG",
                                 "^(FILTER smtp-amavis:\\[127.0.0.1\\]:10029\n)$": "STRONG",
                                 "^(strong_check_recipient_restrictions|strong_check_sender_restrictions)$": "STRONG",
                                 "^whitelist_sender_restrictions$": "WHITELIST",
                                 "\n": "",
                               }
  for tableType := range inputMap{
    for table := range inputMap[tableType]{
      //Rewrite action for usability
      for expression := range regexpMap{
        re := regexp.MustCompile(expression)
        if re.MatchString(inputMap[tableType][table].(string)){
          inputMap[tableType][table] = re.ReplaceAllString(inputMap[tableType][table].(string), regexpMap[expression])
        }
      }
    }
  }
  //Encode json
  jsonString, _ := json.Marshal(inputMap)
  return string(jsonString)
}

/*
Smart test
 This test analysis all input rules, maps, etc and return result checks:
  Example: your message may be banned as spam
  Example2: your message will be banned if contains attachment
*/
func SmartTestAmavis(from, to string, postfixTables, amavisTables map[string]map[string]map[string]interface{},
                amavisScoreMaps map[string]map[string]interface{},
                amavisConf map[string]string)  (string, error){

  var result string
  resultMap := make(map[string]interface{})
  resultMap["info"] = []string{}
  resultMap["verdict"] = "Passed"
  resultMap["attachment"] = "DEFAULT"
  var maxScores float64
  var initMaxScores bool
  //Check attachment rules
  //Check recipient if sender LIGHT rule
  if postfixTables["senders"]["data_restrictions"]["action"] == "FILTER smtp-amavis:[127.0.0.1]:10028\n" {
    maxScores = extractAmavisParameterFloat(amavisConf[`$policy_bank{'LIGHT'}`])
    result = checkRegexpMap(amavisTables["recipients"]["banned_filename_maps_trusted"], to)
    initMaxScores = true
    resultMap["policy_bank"] = "LIGHT: "+amavisConf[`$policy_bank{'LIGHT'}`]
  } else {
    result = checkRegexpMap(amavisTables["recipients"]["banned_filename_maps_origin"], to)
  }
  if result != "" {
    resultMap["attachment"] = result
    if result == "BLOCK_ALL"{
      resultMap["verdict"] = "Warning"
      resultMap["info"] = append(resultMap["info"].([]string), "If contains any attachment, message to be banned.")
    }
  }

  //If recipient STRONG rule
  if postfixTables["recipients"]["data_restrictions"]["action"] == "FILTER smtp-amavis:[127.0.0.1]:10029\n" {
    /*maxScores needed replace on variable spam_kill_level_maps from amavis config,
      dependenced on "/contentfilter" settings*/
    maxScores = extractAmavisParameterFloat(amavisConf[`$policy_bank{'STRONG'}`])
    initMaxScores = true
    resultMap["policy_bank"] = "STRONG: "+amavisConf[`$policy_bank{'STRONG'}`]
  }
  if !initMaxScores {
      maxScores = extractAmavisParameterFloat(amavisConf[`$sa_tag2_level_deflt`])
  }
  resultMap["maxScores"] = maxScores
  foundPersonalScores, personalScores := calculateScores(amavisScoreMaps, from, to, maxScores)
  if foundPersonalScores {
    resultMap["personalScores"] = personalScores
    if personalScores >= maxScores {
      resultMap["verdict"] = "Spam"
      resultMap["info"] = append(resultMap["info"].([]string), "Message will be marked as spam by scores")
    } else {
      if personalScores <= -5 {
        resultMap["info"] = append(resultMap["info"].([]string), "Message passed by scores")
      }
    }
  }
  //Check score maps
  //Encode json
  jsonString, _ := json.Marshal(resultMap)
  return string(jsonString), nil
}

func calculateScores(amavisScoreMaps map[string]map[string]interface{}, from, to string, maxScores float64)  (bool, float64){
  //Check per recipient score maps
  var scores float64
  var action string
  for recipient := range amavisScoreMaps{
    re, _ := pcre.Compile(recipient, 0)
    matcher := re.MatcherString(to, 0)
    match := matcher.Matches()
    if match {
      /*scoresRecipientBySender:
       map[map:[map[src:.*exampleUser.lan dst:+15 priority:0] map[src:.dx.lan dst:+15 priority:1]] priority:0]*/
      scoresRecipientBySender := checkRegexpMap(amavisScoreMaps[recipient], from)
      if scoresRecipientBySender != ""{
        pattern := regexp.MustCompile(`^(?P<action>[\+|\-]|)(?P<scores>\d|\d\d|\d+\.\d+)$`)
        actionByte := []byte{}
        scoresByte := []byte{}
        for _, submatches := range pattern.FindAllStringSubmatchIndex(scoresRecipientBySender, -1) {
          // Apply the captured submatches to the template and append the output
          // to the result.
          actionByte = pattern.ExpandString(actionByte, "$action", scoresRecipientBySender, submatches)
          if string(actionByte) == "" {action = "="} else {action = string(actionByte)}
          scoresByte := pattern.ExpandString(scoresByte, "$scores", scoresRecipientBySender, submatches)
          scores, _ = strconv.ParseFloat(string(scoresByte), 64)
        }
        var delta float64
        if action == "+" {
          delta = scores-maxScores
        }
        if action == "-" {
          delta = maxScores-scores
        }
        if action == "=" {
          delta = scores
        }
        return true, delta
      }
    }
  }
  return false, 0
}

func extractAmavisParameterFloat(content string)  float64{
  patterns := []string{`^.*spam_kill_level_maps.*=> +\( +(?P<result>\d+\.\d+).*$`,
                        `^.*spam_kill_level_maps.*=> +\( +(?P<result>\d+\.\d+) +\),.*$`,
                        `^(?P<result>\d\.\d).*;$`}
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    template := "$result"
    for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
      // Apply the captured submatches to the template and append the output
      // to the result.
      result = pattern.ExpandString(result, template, content, submatches)
    }
  }
  resultFloat, _ := strconv.ParseFloat(string(result), 64)
  return resultFloat
}

func checkRegexpMap(inputMap map[string]interface{}, address string) string {
  regexpMaps := inputMap["map"].([]interface{})
  for filenameMap := range regexpMaps {
     recipientFilenameRule := regexpMaps[filenameMap].(map[string]interface{})
     //Check pcre
     re, _ := pcre.Compile(recipientFilenameRule["src"].(string), 0)
     matcher := re.MatcherString(address, 0)
     match := matcher.Matches()
     if match {
       return recipientFilenameRule["dst"].(string)
     }
  }
  return ""
}

func CheckRelayDomain(relay_domains []string, to string) bool{
  exist := false
  for domain := range relay_domains{
    if !exist{
      domain_template := `^.*@`+relay_domains[domain]+`$`
      re, _ := pcre.Compile(domain_template, 0)
      matcher := re.MatcherString(to, 0)
      exist = matcher.Matches()
    }
  }
  return exist
}
/*
 Create map for recipient in format:
  sexampleUser@example.lan:
    {priority: 0
    senders:
      [{src: ya.lan, dst: +15, priority: 0}]}
*/
func MapRecipientScoreSenderAmavis(hashString string)  (map[string]map[string]interface{}, error){
  removeSymbols := strings.NewReplacer("{", "",
                                       "};", "")
  hashString = removeSymbols.Replace(hashString)
  recipients := strings.Split(hashString, `)], `)
  result := make(map[string]map[string]interface{})
  for i := range recipients{ if recipients[i] != ""{
      recipientParams := strings.Split(recipients[i], "  =>  ")
      senders, err := MapArrayHashRegexpAmavis(recipientParams[1])
      if err != nil{ return nil, err }
      recipient := extractAmavisExpression(recipientParams[0])
      result[recipient] = senders
      result[recipient]["priority"] = i
    }
  }
  return result, nil
}

/*
Convert this map:
 sexampleUser@example.lan:
  {priority: 0
  senders:
    [{src: ya.lan, dst: +15, priority: 0}]}
To usability score-map json:
{
	"maps": [{
			"recipient": "sexampleUser@example.lan",
			"priority": 0,
			"senders": [{
				"priority": 0,
				"scores": "+15",
				"sender": ".dx.lan"
			}, {
				"priority": 1,
				"scores": "+15",
				"sender": "exampleUser.lan"
			}]
		},
		{
			"recipient": "sexampleUser@example.lan",
			"priority": 1,
			"senders": [{
				"priority": 0,
				"scores": "+15",
				"sender": ".dx.lan"
			}, {
				"priority": 1,
				"scores": "+15",
				"sender": "exampleUser.lan"
			}]
		}
	]
}
*/
func MapScoreMaps(inputMap map[string]map[string]interface{})  string{
  type rule struct{
    Sender string
    Scores string
    Priority int
  }
  type scoreMap struct{
    Recipient string
    Priority int
    Senders []rule
  }
  var scoreMaps []interface{}

  for recipient := range inputMap{
    var scoreResult scoreMap
    var scoreRules []rule
    for inputRules := range inputMap[recipient]{
      sendersRuleArrays, ok := inputMap[recipient][inputRules].([]interface{})
      if ok {
        for i := range sendersRuleArrays{
          inputRule := sendersRuleArrays[i].(map[string]interface{})
          var scoreRule rule
          scoreRule.Sender = inputRule["src"].(string)
          scoreRule.Scores = inputRule["dst"].(string)
          scoreRule.Priority = inputRule["priority"].(int)
          scoreRules = append(scoreRules, scoreRule)
        }
      } else {
        scoreResult.Priority = inputMap[recipient][inputRules].(int)
      }
    }
    scoreResult.Senders = scoreRules
    scoreResult.Recipient = recipient
    //Lower field names, convert parameters to map and append to result
    scoreMaps = append(scoreMaps, structs.Map(scoreResult))
  }
  result := map[string]interface{}{"maps": scoreMaps}
  //Encode json
  jsonString, _ := json.Marshal(result)
  return string(jsonString)
}
