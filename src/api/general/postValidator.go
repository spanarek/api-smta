package general

import "gopkg.in/validator.v2"
import ("encoding/json"
        "io")
import "github.com/fatih/structs"
import "errors"
import "crypto/tls"

/*Check incoming "general" and "ssl" group parameters from json request
and generate map array for postfix.UpdateMainCf method*/
func ValidateGeneral(inputParams io.Reader, location string) (map[string]interface{}, error){
  type mainParams struct {
    Smtpd_banner string `validate:"min=3, max=90"`
    //regexp for email address:
    Double_bounce_sender string `validate:"min=3,max=90,regexp=^[^\\.].*@.*\\..*.[^\\.]$"`
    //message size in bytes:
    Message_size_limit int `validate:"min=1024, max=1073741824"`
    Unverified_sender_reject_code int `validate:"min=100, max=999"`
    Unknown_address_reject_code int `validate:"min=100, max=999"`
    Unknown_local_recipient_reject_code int `validate:"min=100, max=999"`
  }
  type sslParams struct {
    Smtpd_use_tls string `validate:"regexp=^(yes|no)$"`
    Smtp_tls_loglevel int `validate:"min=0, max=4"`
    Smtp_tls_security_level string `validate:"regexp=^(none|may|encrypt|dane|dane-only|fingerprint|verify|secure)$"`
    Smtpd_tls_security_level string `validate:"regexp=^(none|may|encrypt)$"`
    Smtpd_tls_received_header string `validate:"regexp=^(yes|no)$"`
    Smtpd_tls_session_cache_timeout string `validate:"min=0, max=8", regexp=^\\d+s$`
  }
  var result map[string]interface{}
  var err error
  switch location{
  default:
    return nil, errors.New("Unknown location")
  case "main":
    var tmpParams mainParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err = decoder.Decode(&tmpParams)
    if err !=nil{
      return nil, err
    }
    //Validate parameters from json:
    err = validator.Validate(tmpParams)
    if err !=nil{
      return nil, err
    }
    /*If validate and decoder success:
      Lower field names and convert parameters to map for return:*/
    result = structs.Map(tmpParams)
  case "ssl":
    var tmpParams sslParams
    //Decode json data:
    decoder := json.NewDecoder(inputParams)
    err = decoder.Decode(&tmpParams)
    if err !=nil{
      return nil, err
    }
    //Validate parameters from json:
    err = validator.Validate(tmpParams)
    if err !=nil{
      return nil, err
    }
    /*If validate and decoder success:
      Lower field names and convert parameters to map for return:*/
    result = structs.Map(tmpParams)
  }

  return result, err
}

/*Check incoming cert group parameters.
Check certificate and key.
Return certificate and key as strings from extracted incoming json.*/
func ValidateCert(inputParams io.Reader) (string, string, error) {
  type certParams struct {
    Cert string
    Key string
  }
  var tmpParams certParams
  var err error
  //Decode json data:
  decoder := json.NewDecoder(inputParams)
  err = decoder.Decode(&tmpParams)
  if err !=nil{
    return "", "", err
  }
  //Validate cert and key file via crypto/tls library:
  _, err = tls.X509KeyPair([]byte(tmpParams.Cert), []byte(tmpParams.Key))
  return tmpParams.Cert, tmpParams.Key, err
}
