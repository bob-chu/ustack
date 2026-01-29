pub const @"build.build.LogLevel" = enum (u3) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,
    none = 4,
};
pub const log_level: @"build.build.LogLevel" = .warn;
