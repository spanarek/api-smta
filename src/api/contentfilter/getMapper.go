package contentfilter

import  "encoding/json"
import ("regexp"
        "strconv")
import "strings"
import "os"
import "time"

//Mapping main group parameters from amavis configuration
func MapMain(amavisConf map[string]string) string{
  //Create map:
  result := map[string]interface{}{
    "enable_dkim_verification": extractAmavisParameterFloat(amavisConf["$enable_dkim_verification"]),
    "bounce_killer_score": extractAmavisParameterFloat(amavisConf["$bounce_killer_score"]),
    "final_spam_destiny": extractAmavisStringParameter(amavisConf["$final_spam_destiny"]),
    "final_virus_destiny": extractAmavisStringParameter(amavisConf["$final_virus_destiny"]),
    "final_banned_destiny": extractAmavisStringParameter(amavisConf["$final_banned_destiny"]),
    "final_bad_header_destiny": extractAmavisStringParameter(amavisConf["$final_bad_header_destiny"]),
    "quarantine_dir": extractAmavisStringParameter(amavisConf["$QUARANTINEDIR"]),
    "log_level": extractAmavisParameterFloat(amavisConf["$log_level"]),
    "do_syslog": extractAmavisParameterFloat(amavisConf["$do_syslog"]),
    "sa_mail_body_size_limit": extractAmavisParameterFloat(amavisConf["$sa_mail_body_size_limit"]),
    "sa_tag2_level_deflt": extractAmavisParameterFloat(amavisConf["$sa_tag2_level_deflt"]),
    "sa_kill_level_deflt": extractAmavisParameterFloat(amavisConf["$sa_kill_level_deflt"]),
    "sa_spam_subject_tag": extractAmavisStringParameter(amavisConf["$sa_spam_subject_tag"]),
    "undecipherable_subject_tag": extractAmavisStringParameter(amavisConf["$undecipherable_subject_tag"]),
    "banned_filename_re": extractAmavisRegexpArrayParameter(amavisConf["$banned_filename_re"]),
  }
  //Encode json amavis configuration:
  jsonString, _ := json.Marshal(result)
  //If success encode return JSON array
  return string(jsonString)
}

//Extracting float64 from parameter amavis configuration
func extractAmavisParameterFloat(content string)  float64{
  patterns := []string{`(?P<result>\d+)\*1024;$`,
                       `(?P<result>\d\.\d+);$`,
                       `(?P<result>\d+);$`,
                    }
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    if pattern.MatchString(content) {
      template := "$result"
      for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
        // Apply the captured submatches to the template and append the output
        // to the result.
        result = pattern.ExpandString(result, template, content, submatches)
      }
    }
  }
  resultFloat, _ := strconv.ParseFloat(string(result), 64)
  return resultFloat
}

//Extracting string from parameter amavis configuration
func extractAmavisStringParameter(content string)  string{
  patterns := []string{`(?P<result>\w+);$`,
                       `^\"(?P<result>(/[^/ ]*)+/?)\";$`,
                       `^'(?P<result>.*)';$`,
                    }
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    if pattern.MatchString(content){
      template := "$result"
      for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
        // Apply the captured submatches to the template and append the output
        // to the result.
        result = pattern.ExpandString(result, template, content, submatches)
      }
    }
  }

  stringParameter := string(result)
  return stringParameter
}

/*Extracting array regexp from parameter amavis configuration
 Example:
  new_RE(qr'^UNDECIPHERABLE$', qr'.\.(pif|scr)$'i, qr'^application/x-msdownload$'i, qr'^application/x-msdos-program$'i, qr'^application/hta$'i,  qr'^(?!cid:).*\.[^./]*[A-Za-z][^./]*\.\s*(exe|vbs|pif|scr|bat|cmd|com|cpl|dll)[.\s]*$'i, qr'.\.(ade|adp|app|bas|bat|chm|cmd|com|cpl|crt|emf|exe|fxp|grp|hlp|hta|inf|ini|ins|isp|js|jse|jsp|lib|lnk|mda|mdb|mde|mdt|mdw|mdz|msc|msi|msp|mst|ocx|ops|pcd|pif|prg|reg|scr|sct|shb|shs|sys|vb|vbe|vbs|vxd|wmf|wsc|wsf|wsh)$'ix);
*/
func extractAmavisRegexpArrayParameter(content string)  []string{
  reString := `^new_RE\((?P<result>.*)\);`
  re := regexp.MustCompile(reString)
  reResult := []byte{}
  for _, submatches := range re.FindAllStringSubmatchIndex(content, -1) {
    // Apply the captured submatches to the template and append the output
    // to the result.
    reResult = re.ExpandString(reResult, "$result", content, submatches)
  }
  resultRaw := strings.Split(string(reResult), ",   ")
  result := []string{}
  for pcreExpression := range resultRaw{
    result = append(result, extractAmavisPCREExpression(resultRaw[pcreExpression]))
  }
  return result
}

//Extract regular expression body
func extractAmavisPCREExpression(content string) string{
  patterns := []string{`(?m)^qr'(?P<result>.*)'\w+$`,
                       `(?m)^qr'(?P<result>.*)'$`}
  result := []byte{}
  for i := 0; (i<len(patterns) && string(result) == ""); i++ {
    pattern := regexp.MustCompile(patterns[i])
    if pattern.MatchString(content){
      template := "$result"
      for _, submatches := range pattern.FindAllStringSubmatchIndex(content, -1) {
        // Apply the captured submatches to the template and append the output
        // to the result.
        result = pattern.ExpandString(result, template, content, submatches)
      }
    }
  }
  return string(result)
}

//Create quarantine list json
func MapQuarantineList(files []os.FileInfo, slimit, dateStart, dateEnd string)  (string, error){
  result := map[string]interface{}{}
  var err error
  var limit int
  if slimit == "" {
    limit = 10
  } else {
    limit, err = strconv.Atoi(slimit)
    if err != nil {
      return "", err
    }
  }

  if dateStart == "" || dateEnd == "" {
    for i:= range files{
      if i < limit{
       result[files[i].Name()] = files[i].ModTime().UTC()
      }
    }
  } else {
    //Array filling by date start and date end
    var TdateEnd, TdateStart time.Time
    TdateStart, err = time.Parse(time.RFC3339Nano, dateStart)
    if err != nil {
      return "", err
    }
    TdateEnd, err = time.Parse(time.RFC3339Nano, dateEnd)
    if err != nil {
      return "", err
    }

    for i:= range files{
      if i < limit {
        if files[i].ModTime().Unix() >= TdateStart.Unix() && files[i].ModTime().Unix() <= TdateEnd.Unix(){
          result[files[i].Name()] = files[i].ModTime().UTC()
        }
        }
    }
  }

  //Encode json files list:
  jsonString, _ := json.Marshal(result)
  //If success encode return JSON array
  return string(jsonString), nil
}

func MapQuarantineMessageHeaders(rawHeaders map[string]string)  string{
  //Encode json files list:
  jsonString, _ := json.Marshal(rawHeaders)
  //If success encode return JSON array
  return string(jsonString)
}
