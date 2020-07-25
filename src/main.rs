
use nu_errors::ShellError;
use nu_plugin::{serve_plugin, Plugin};
use nu_source::Tag;
use nu_protocol::{
    CallInfo, ReturnSuccess, ReturnValue, Signature, Dictionary, UntaggedValue, Value,
};

#[macro_use] extern crate indexmap;

use wifiscanner::{Wifi, scan};

fn strip(ap: &Wifi, tag: Tag) -> Value {
    let entries = indexmap!{
      "ssid".to_string() => Value { value: UntaggedValue::string(ap.ssid.as_str()), tag: tag.clone() },
      "mac".to_string() => Value { value: UntaggedValue::string(ap.mac.as_str()), tag: tag.clone() },
      "channel".to_string() => Value { value: UntaggedValue::string(ap.channel.as_str()), tag: tag.clone() },
      "signal_level".to_string() => Value { value: UntaggedValue::string(ap.signal_level.as_str()), tag: tag.clone() },
      "security".to_string() => Value { value: UntaggedValue::string(ap.security.as_str()), tag: tag.clone() }
    };
    Value { value: UntaggedValue::Row(Dictionary { entries: entries }), tag: tag }
}

struct WiFiScan;

impl WiFiScan {
    fn new() -> WiFiScan {
        WiFiScan
    }
}

impl Plugin for WiFiScan {
    fn config(&mut self) -> Result<Signature, ShellError> {
        Ok(Signature::build("wifiscan").desc("My test wifiscan plugin").filter())
    }

    fn begin_filter(&mut self, _: CallInfo) -> Result<Vec<ReturnValue>, ShellError> {
        Ok(vec![])
    }

    fn filter(&mut self, input: Value) -> Result<Vec<ReturnValue>, ShellError> {
        match scan() {
            Ok(r) => {
                eprintln!("WiFi scanning: {:?}", r);
                Ok(r.iter().map(|w| { ReturnSuccess::value(strip(w, input.tag.clone())) }).collect())
            },
            Err(err) => {
                eprintln!("WiFi fail: {:?}", err);
                Err(ShellError::labeled_error("q", "w", input.tag.span))
            }
        }
    }
}

fn main() {
    serve_plugin(&mut WiFiScan::new());
}
