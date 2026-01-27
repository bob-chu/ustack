const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const LogLevel = enum {
        err,
        warn,
        info,
        debug,
        none,
    };
    const log_level = b.option(LogLevel, "log_level", "Log level for ustack (default: debug)") orelse .debug;

    const options = b.addOptions();
    options.addOption(LogLevel, "log_level", log_level);
    const options_mod = options.createModule();

    const lib = b.addStaticLibrary(.{
        .name = "ustack",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.root_module.addImport("build_options", options_mod);
    b.installArtifact(lib);

    const dylib = b.addSharedLibrary(.{
        .name = "ustack",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    dylib.root_module.addImport("build_options", options_mod);
    b.installArtifact(dylib);

    const ustack_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
    });
    ustack_mod.addImport("build_options", options_mod);

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_tests.root_module.addImport("build_options", options_mod);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const example_step = b.step("example", "Build libev examples");

    // Add other examples
    const examples = [_]struct { name: []const u8, path: []const u8, lib: []const u8 }{
        .{ .name = "example_tap_libev", .path = "examples/main_tap_libev.zig", .lib = "ev" },
        .{ .name = "example_tap_libev_mux", .path = "examples/main_tap_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev", .path = "examples/main_af_packet_libev.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev_mux", .path = "examples/main_af_packet_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_xdp_libev", .path = "examples/main_af_xdp_libev.zig", .lib = "ev" },
        .{ .name = "example_unified", .path = "examples/main_unified.zig", .lib = "ev" },
        .{ .name = "example_iperf_libev", .path = "examples/iperf.zig", .lib = "ev" },
    };

    for (examples) |ex| {
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("ustack", ustack_mod);
        // exe.linkLibrary(lib);
        exe.linkLibC();

        exe.linkSystemLibrary(ex.lib);
        if (std.mem.eql(u8, ex.name, "example_tap_libev") or
            std.mem.eql(u8, ex.name, "example_tap_libev_mux") or
            std.mem.eql(u8, ex.name, "example_af_packet_libev") or
            std.mem.eql(u8, ex.name, "example_af_packet_libev_mux") or
            std.mem.eql(u8, ex.name, "example_unified") or
            std.mem.eql(u8, ex.name, "example_iperf_libev") or
            std.mem.eql(u8, ex.name, "example_af_xdp_libev"))
        {
            exe.addCSourceFile(.{ .file = b.path("examples/wrapper.c"), .flags = &.{ "-I/usr/include", "-I/usr/local/include" } });
        }
        const install = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&install.step);
    }
}
