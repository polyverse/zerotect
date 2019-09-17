
extern crate sys_info;
extern crate sysctl;

use sys_info::{os_type};
use sysctl::Sysctl;

pub fn ensure_linux() {
    const OS_DETECT_FAILURE: &str = "Unable to detect Operating System type. This program modifies the operating system in fundamental ways and fails safely when unable to detect the operating system.";
    let osname = os_type().expect(OS_DETECT_FAILURE);
    if osname != "Linux" {
        panic!("The Operating System detected is {} and not supported. This program modifies operating system settings in funamental ways and thus fails safely when it is not supported.", osname)
    }
}

pub fn modify_environment(config: &PolytectParams) {
    eprintln!("Configuring kernel paramters as requested...");
    if let Some(exception_trace) = config.exception_trace {
        ensure_systemctl(EXCEPTION_TRACE_CTLNAME, bool_to_sysctl_string(exception_trace));
    }

    if let Some(fatal_signals) = config.fatal_signals {
        ensure_systemctl(PRINT_FATAL_SIGNALS_CTLNAME, bool_to_sysctl_string(fatal_signals));
    }
}

fn ensure_systemctl(ctlstr: &str, valuestr: &str) {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let exception_trace_ctl = sysctl::Ctl::new(ctlstr).unwrap();
    let prev_value_str = exception_trace_ctl.value_string().expect(format!("Unable to read value of {}", ctlstr).as_str());
    if prev_value_str ==  valuestr {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
    } else {
        let real_value_str = exception_trace_ctl.set_value_string(valuestr)
            .expect(format!("Unable to set value of {} to {}, from a previous value of {}", ctlstr, valuestr, prev_value_str).as_str());
        assert!(real_value_str == valuestr, "The value of {} was set to {} successfully, but value returned {}.", ctlstr, valuestr, real_value_str)
    }
}

fn bool_to_sysctl_string(b: bool) -> &'static str {
    match b {
        false => "0",
        true => "1"
    }
}
