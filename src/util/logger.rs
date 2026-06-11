//! Pluggable logging.
//!
//! The engine never writes to stdout/stderr itself; it hands structured log
//! records to whatever [`Logger`] the embedder provides. A no-op logger and a
//! stderr logger are included.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        };
        f.write_str(s)
    }
}

/// A log record. `module` is the crate-internal source; `peer`/`channel`
/// give context when the record concerns a specific peer or channel.
pub struct Record<'a> {
    pub level: Level,
    pub module: &'static str,
    pub message: fmt::Arguments<'a>,
}

pub trait Logger {
    fn log(&self, record: Record<'_>);
}

/// Discards all records.
pub struct NullLogger;

impl Logger for NullLogger {
    fn log(&self, _record: Record<'_>) {}
}

/// Writes records to stderr; useful for examples and tests.
pub struct StderrLogger {
    pub min_level: Level,
}

impl Logger for StderrLogger {
    fn log(&self, record: Record<'_>) {
        if record.level >= self.min_level {
            eprintln!("[{} {}] {}", record.level, record.module, record.message);
        }
    }
}

/// `log!(logger, Level::Info, "...")` — each convenience macro below is
/// self-contained so call sites only need to import the one they use.
#[allow(unused_macros)]
macro_rules! log {
    ($logger:expr, $level:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $level,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}

#[allow(unused_macros)]
macro_rules! log_trace {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $crate::util::logger::Level::Trace,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $crate::util::logger::Level::Debug,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $crate::util::logger::Level::Info,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $crate::util::logger::Level::Warn,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::util::logger::Record {
            level: $crate::util::logger::Level::Error,
            module: module_path!(),
            message: format_args!($($arg)*),
        })
    };
}

#[allow(unused_imports)]
pub(crate) use {log, log_debug, log_error, log_info, log_trace, log_warn};
