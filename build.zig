const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const static_link = b.option(bool, "static", "Build static binaries") orelse false;
    const libev_prefix_opt = b.option([]const u8, "libev_prefix", "Prefix path for libev headers/libs (e.g. /usr/local/musl)");

    const resolved_target = target.result;
    const is_linux_x86_64_gnu = resolved_target.os.tag == .linux and
        resolved_target.cpu.arch == .x86_64 and
        resolved_target.abi == .gnu;
    const is_linux_x86_64_musl = resolved_target.os.tag == .linux and
        resolved_target.cpu.arch == .x86_64 and
        resolved_target.abi == .musl;
    const exe_linkage: ?std.builtin.LinkMode = if (static_link or is_linux_x86_64_musl) .static else null;

    const libev_prefix = libev_prefix_opt orelse if (is_linux_x86_64_musl) "/usr/local/musl" else "";
    const libev_include_path = if (libev_prefix.len > 0) b.pathJoin(&.{ libev_prefix, "include" }) else "";
    const libev_lib_path = if (libev_prefix.len > 0) b.pathJoin(&.{ libev_prefix, "lib" }) else "";

    const LogLevel = enum {
        err,
        warn,
        info,
        debug,
        none,
    };
    const log_level = b.option(LogLevel, "log_level", "Log level for ustack (default: info)") orelse .info;

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
    main_tests.linkLibC();
    if (is_linux_x86_64_gnu) {
        main_tests.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });
        main_tests.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
        main_tests.root_module.addIncludePath(.{ .cwd_relative = "/usr/include" });
        main_tests.root_module.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
    } else if (is_linux_x86_64_musl and libev_prefix.len > 0) {
        main_tests.addLibraryPath(.{ .cwd_relative = libev_lib_path });
        main_tests.addIncludePath(.{ .cwd_relative = libev_include_path });
        main_tests.root_module.addIncludePath(.{ .cwd_relative = libev_include_path });
    }
    main_tests.linkSystemLibrary("ev");
    main_tests.addCSourceFile(.{ .file = b.path("examples/wrapper.c"), .flags = &.{ "-I/usr/include", "-I/usr/include/x86_64-linux-gnu", "-I/usr/local/include" } });

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const example_step = b.step("example", "Build libev examples");

    // Add other examples
    const examples = [_]struct { name: []const u8, path: []const u8, lib: []const u8 }{
        .{ .name = "example_ping_pong", .path = "examples/ping_pong.zig", .lib = "ev" },
        .{ .name = "example_tap_libev", .path = "examples/main_tap_libev.zig", .lib = "ev" },
        .{ .name = "example_tap_libev_mux", .path = "examples/main_tap_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev", .path = "examples/main_af_packet_libev.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev_mux", .path = "examples/main_af_packet_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_xdp_libev", .path = "examples/main_af_xdp_libev.zig", .lib = "ev" },
        .{ .name = "example_unified", .path = "examples/main_unified.zig", .lib = "ev" },
        .{ .name = "example_uperf_libev", .path = "examples/uperf.zig", .lib = "ev" },
        .{ .name = "example_uperf_socket", .path = "examples/uperf_socket.zig", .lib = "ev" },
        // ...
        .{ .name = "example_uperf_runtime", .path = "examples/uperf_runtime.zig", .lib = "ev" },
        .{ .name = "example_ping_pong_socket", .path = "examples/ping_pong_socket.zig", .lib = "ev" },
        .{ .name = "example_uperf_fd", .path = "examples/uperf_fd.zig", .lib = "ev" },
        .{ .name = "example_uperf_linux", .path = "examples/uperf_linux.zig", .lib = "ev" },
        .{ .name = "example_ping_pong_linux", .path = "examples/ping_pong_linux.zig", .lib = "ev" },
        .{ .name = "example_ping_pong_fd", .path = "examples/ping_pong_fd.zig", .lib = "ev" },
    };

    for (examples) |ex| {
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
            .linkage = exe_linkage,
        });
        exe.root_module.addImport("ustack", ustack_mod);
        // exe.linkLibrary(lib);
        exe.linkLibC();
        if (is_linux_x86_64_gnu) {
            exe.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });
            exe.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
            exe.root_module.addIncludePath(.{ .cwd_relative = "/usr/include" });
            exe.root_module.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
        } else if (is_linux_x86_64_musl and libev_prefix.len > 0) {
            exe.addLibraryPath(.{ .cwd_relative = libev_lib_path });
            exe.addIncludePath(.{ .cwd_relative = libev_include_path });
            exe.root_module.addIncludePath(.{ .cwd_relative = libev_include_path });
        }

        exe.linkSystemLibrary(ex.lib);
        if (std.mem.eql(u8, ex.name, "example_tap_libev") or
            std.mem.eql(u8, ex.name, "example_tap_libev_mux") or
            std.mem.eql(u8, ex.name, "example_af_packet_libev") or
            std.mem.eql(u8, ex.name, "example_af_packet_libev_mux") or
            std.mem.eql(u8, ex.name, "example_unified") or
            std.mem.eql(u8, ex.name, "example_uperf_libev") or
            std.mem.eql(u8, ex.name, "example_uperf_socket") or
            std.mem.eql(u8, ex.name, "example_uperf_runtime") or
            std.mem.eql(u8, ex.name, "example_af_xdp_libev") or
            std.mem.eql(u8, ex.name, "example_ping_pong") or
            std.mem.eql(u8, ex.name, "example_ping_pong_socket") or
            std.mem.eql(u8, ex.name, "example_ping_pong_linux") or
            std.mem.eql(u8, ex.name, "example_uperf_linux") or
            std.mem.eql(u8, ex.name, "example_uperf_fd") or
            std.mem.eql(u8, ex.name, "example_ping_pong_fd"))
        {
            exe.addCSourceFile(.{ .file = b.path("examples/wrapper.c"), .flags = &.{ "-I/usr/include", "-I/usr/include/x86_64-linux-gnu", "-I/usr/local/include" } });
        }
        const install = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&install.step);

        if (std.mem.eql(u8, ex.name, "example_ping_pong_fd")) {
            const step = b.step("ping_pong_fd", "Build the ping_pong_fd example");
            step.dependOn(&install.step);
        }
    }
}
