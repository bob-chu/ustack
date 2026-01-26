const std = @import("std");
const build_options = @import("build_options");

pub const Level = enum { err, warn, info, debug, none };

pub const log_level: Level = switch (build_options.log_level) {
    .err => .err,
    .warn => .warn,
    .info => .info,
    .debug => .debug,
    .none => .none,
};

pub fn err(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.err) <= @intFromEnum(log_level)) {
        std.log.err(format, args);
    }
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.warn) <= @intFromEnum(log_level)) {
        std.log.warn(format, args);
    }
}

pub fn info(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.info) <= @intFromEnum(log_level)) {
        std.log.info(format, args);
    }
}

pub fn debug(comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.debug) <= @intFromEnum(log_level)) {
        std.log.debug(format, args);
    }
}

/// Helper for conditional logging based on a scope
pub fn scoped(comptime scope: @Type(.EnumLiteral)) type {
    return struct {
        pub fn err(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.err) <= @intFromEnum(log_level)) {
                std.log.scoped(scope).err(format, args);
            }
        }

        pub fn warn(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.warn) <= @intFromEnum(log_level)) {
                std.log.scoped(scope).warn(format, args);
            }
        }

        pub fn info(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.info) <= @intFromEnum(log_level)) {
                std.log.scoped(scope).info(format, args);
            }
        }

        pub fn debug(comptime format: []const u8, args: anytype) void {
            if (@intFromEnum(log_level) != @intFromEnum(Level.none) and @intFromEnum(Level.debug) <= @intFromEnum(log_level)) {
                std.log.scoped(scope).debug(format, args);
            }
        }
    };
}
