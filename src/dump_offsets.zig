const std = @import("std");
const tcp = @import("src/transport/tcp.zig");
const buffer = @import("src/buffer.zig");
const waiter = @import("src/waiter.zig");

pub fn main() void {
    const stdout = std.io.getStdOut().writer();

    stdout.print("Sizes:\n", .{}) catch {};
    stdout.print("  Allocator: {}\n", .{@sizeOf(std.mem.Allocator)}) catch {};
    stdout.print("  BufferPool: {}\n", .{@sizeOf(buffer.BufferPool)}) catch {};
    stdout.print("  Pool(TCPEndpoint): {}\n", .{@sizeOf(buffer.Pool(tcp.TCPEndpoint))}) catch {};
    stdout.print("  TCPProtocol: {}\n", .{@sizeOf(tcp.TCPProtocol)}) catch {};
    stdout.print("  TCPEndpoint: {}\n", .{@sizeOf(tcp.TCPEndpoint)}) catch {};

    stdout.print("\nTCPProtocol offsets:\n", .{}) catch {};
    inline for (std.meta.fields(tcp.TCPProtocol)) |f| {
        stdout.print("  {s}: 0x{x}\n", .{ f.name, @offsetOf(tcp.TCPProtocol, f.name) }) catch {};
    }

    stdout.print("\nTCPEndpoint offsets:\n", .{}) catch {};
    inline for (std.meta.fields(tcp.TCPEndpoint)) |f| {
        stdout.print("  {s}: 0x{x}\n", .{ f.name, @offsetOf(tcp.TCPEndpoint, f.name) }) catch {};
    }
}
