package general

import  "encoding/json"
import  "strconv"

//Mapping main group parameters from main.cf configuration
func MapMain(postfixMainCf map[string][]string) string{
  //Convert some parameters to int:
  message_size_limit, _:= strconv.Atoi(postfixMainCf["message_size_limit"][0])
  unverified_sender_reject_code, _:= strconv.Atoi(postfixMainCf["unverified_sender_reject_code"][0])
  unknown_address_reject_code, _:= strconv.Atoi(postfixMainCf["unknown_address_reject_code"][0])
  unknown_local_recipient_reject_code, _:= strconv.Atoi(postfixMainCf["unknown_local_recipient_reject_code"][0])
  //Create map:
  result := map[string]interface{}{
    "smtpd_banner": postfixMainCf["smtpd_banner"][0],
    "message_size_limit": message_size_limit,
    "double_bounce_sender": postfixMainCf["double_bounce_sender"][0],
    "unverified_sender_reject_code": unverified_sender_reject_code,
    "unknown_address_reject_code": unknown_address_reject_code,
    "unknown_local_recipient_reject_code": unknown_local_recipient_reject_code,
  }
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(result)
  //If success encode return JSON array
  return string(jsonString)
}

//Mapping SSL group parameters from main.cf configuration
func MapSSL(postfixMainCf map[string][]string) string{
  //Convert some parameters to int:
  smtp_tls_loglevel, _:= strconv.Atoi(postfixMainCf["smtp_tls_loglevel"][0])
  //Create map:
  result := map[string]interface{}{
    "smtpd_use_tls": postfixMainCf["smtpd_use_tls"][0],
    "smtp_tls_loglevel": smtp_tls_loglevel,
    "smtp_tls_security_level": postfixMainCf["smtp_tls_security_level"][0],
    "smtpd_tls_security_level": postfixMainCf["smtpd_tls_security_level"][0],
    "smtpd_tls_received_header": postfixMainCf["smtpd_tls_received_header"][0],
    "smtpd_tls_session_cache_timeout": postfixMainCf["smtpd_tls_session_cache_timeout"][0],
  }
  //Encode json postfix configuration:
  jsonString, _ := json.Marshal(result)
  //If success encode return JSON array
  return string(jsonString)
}
