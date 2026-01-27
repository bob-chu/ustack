const std = @import("std");
const build_options = @import("build_options");

pub const Level = enum(u8) {
    none = 0,
    err = 1,
    warn = 2,
    info = 3,
    debug = 4,
};

pub const log_level: Level = switch (build_options.log_level) {
    .err => .err,
    .warn => .warn,
    .info => .info,
    .debug => .debug,
    .none => .none,
};

pub fn err(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) >= @intFromEnum(Level.err)) {
        std.debug.print("ERR: " ++ format ++ "\n", args);
    }
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) >= @intFromEnum(Level.warn)) {
        std.debug.print("WARN: " ++ format ++ "\n", args);
    }
}

pub fn info(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) >= @intFromEnum(Level.info)) {
        std.debug.print("INFO: " ++ format ++ "\n", args);
    }
}

pub fn debug(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) >= @intFromEnum(Level.debug)) {
        std.debug.print("DEBUG: " ++ format ++ "\n", args);
    }
}

/// Helper for conditional logging based on a scope
pub fn scoped(comptime scope: @Type(.EnumLiteral)) type {
    return struct {
        pub fn err(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) >= @intFromEnum(Level.err)) {
                std.debug.print("ERR(" ++ @tagName(scope) ++ "): " ++ format ++ "\n", args);
            }
        }

        pub fn warn(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) >= @intFromEnum(Level.warn)) {
                std.debug.print("WARN(" ++ @tagName(scope) ++ "): " ++ format ++ "\n", args);
            }
        }

        pub fn info(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) >= @intFromEnum(Level.info)) {
                std.debug.print("INFO(" ++ @tagName(scope) ++ "): " ++ format ++ "\n", args);
            }
        }

        pub fn debug(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) >= @intFromEnum(Level.debug)) {
                std.debug.print("DEBUG(" ++ @tagName(scope) ++ "): " ++ format ++ "\n", args);
            }
        }
    };
}
