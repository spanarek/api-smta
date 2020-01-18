package contentfilter

import ("encoding/json"
        "io"
        "strconv")
import "gopkg.in/validator.v2"
import "github.com/gijsbers/go-pcre"
import "regexp"
import "errors"

type mainParams struct {
        Enable_dkim_verification int `validate:"min=0, max=1"`
        Do_syslog int `validate:"min=0, max=1"`
        Log_level int `validate:"min=0, max=5"`
        Sa_mail_body_size_limit int `validate:"min=0"`
        Bounce_killer_score float64
        Sa_tag2_level_deflt float64
        Sa_kill_level_deflt float64
        Sa_spam_subject_tag string
        Undecipherable_subject_tag string
        Final_spam_destiny string `validate:"regexp=^(D_PASS|D_BOUNCE|D_REJECT|D_DISCARD)$"`
        Final_virus_destiny string `validate:"regexp=^(D_PASS|D_BOUNCE|D_REJECT|D_DISCARD)$"`
        Final_banned_destiny string `validate:"regexp=^(D_PASS|D_BOUNCE|D_REJECT|D_DISCARD)$"`
        Final_bad_header_destiny string `validate:"regexp=^(D_PASS|D_BOUNCE|D_REJECT|D_DISCARD)$"`
        Quarantine_dir string `validate:"regexp=^((/[^/ ]*)+/?)$"`
        Banned_filename_re []string
}

/*Check incoming contentfilter "main" group parameters from json request
and generate map array for postfix.UpdateMainCf method*/
func ValidateMain(inputParams io.Reader, currentConf string) (map[string]string, error){
  var tmpParams mainParams
  var err error
  //Fill struct using current(from amavis.conf) parameters
  err = json.Unmarshal([]byte(currentConf), &tmpParams)
  if err !=nil{
    return nil, err
  }
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err = decoder.Decode(&tmpParams)
  if err !=nil{
    return nil, err
  }
  //Validate parameters via validate maps for struct:
  err = validator.Validate(tmpParams)
  if err !=nil{
    return nil, err
  }
  //Validate and create string from pcre array
  banned_filename_re := "new_RE("
  for expression := range tmpParams.Banned_filename_re{
    //Validate recipient pcre
    _, err := pcre.Compile(tmpParams.Banned_filename_re[expression], 0)
    if err != nil {
      return nil, err
    }
    if expression != 0{
      banned_filename_re = banned_filename_re+",   "
    }
    banned_filename_re = banned_filename_re+"qr'"+tmpParams.Banned_filename_re[expression]+"'"
  }
  banned_filename_re = banned_filename_re+")"

  result := map[string]string{"$enable_dkim_verification": strconv.Itoa(tmpParams.Enable_dkim_verification)+";",
                              "$do_syslog": strconv.Itoa(tmpParams.Do_syslog)+";",
                              "$log_level": strconv.Itoa(tmpParams.Log_level)+";",
                              "$sa_mail_body_size_limit": strconv.Itoa(tmpParams.Sa_mail_body_size_limit)+"*1024;",
                              "$bounce_killer_score": strconv.FormatFloat(tmpParams.Bounce_killer_score, 'f', 1, 64)+";",
                              "$sa_tag2_level_deflt": strconv.FormatFloat(tmpParams.Sa_tag2_level_deflt, 'f', 1, 64)+";",
                              "$sa_kill_level_deflt": strconv.FormatFloat(tmpParams.Sa_kill_level_deflt, 'f', 1, 64)+";",
                              "$sa_spam_subject_tag": "'"+tmpParams.Sa_spam_subject_tag+"';",
                              "$undecipherable_subject_tag": "'"+tmpParams.Undecipherable_subject_tag+"';",
                              "$final_spam_destiny": tmpParams.Final_spam_destiny+";",
                              "$final_virus_destiny": tmpParams.Final_virus_destiny+";",
                              "$final_banned_destiny": tmpParams.Final_banned_destiny+";",
                              "$final_bad_header_destiny": tmpParams.Final_bad_header_destiny+";",
                              "$QUARANTINEDIR": "\""+tmpParams.Quarantine_dir+"\";",
                              "$banned_filename_re": banned_filename_re+";"}

  return result, err
}

func ValidateReleaseMessage(inputParams io.Reader)  (string, string, error){
  type releaseParams struct {
    Id string `validate:"min=1, max=30"`
    Alt_recipients []string
  }
  var tmpParams releaseParams
  var err error
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err = decoder.Decode(&tmpParams)
  if err !=nil{
    return "", "", err
  }
  //Validate parameters from json:
  err = validator.Validate(tmpParams)
  if err !=nil{
    return "", "", err
  }

  //Compile recipients string:
  var recipients string
  for i := range tmpParams.Alt_recipients {
    err = checkEmail(tmpParams.Alt_recipients[i])
    if err !=nil{
      return "", "", err
    } else {
      recipients = recipients+" "+tmpParams.Alt_recipients[i]
    }
  }

  return tmpParams.Id, recipients, nil
}

//Validate email via regexp
func checkEmail(address string)  error{
  reValue := "^[^\\.].*@.*\\..*.[^\\.]$"
  re := regexp.MustCompile(reValue)
  ok := re.MatchString(address)
  if !ok{
    return errors.New("Alternative recipient must be email only: "+address)
  } else {
    return nil
  }
}
