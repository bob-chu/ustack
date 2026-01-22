const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "ustack",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const dylib = b.addSharedLibrary(.{
        .name = "ustack",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(dylib);

    const ustack_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
    });

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const example = b.addExecutable(.{
        .name = "example_af_packet",
        .root_source_file = b.path("examples/main_af_packet_libuv.zig"),
        .target = target,
        .optimize = optimize,
    });
    example.root_module.addImport("ustack", ustack_mod);
    example.linkLibrary(lib); // Link against static lib to enforce library usage
    example.linkLibC();

    example.linkSystemLibrary("uv");

    const install_example = b.addInstallArtifact(example, .{});
    const example_step = b.step("example", "Build AF_PACKET libuv example");
    example_step.dependOn(&install_example.step);

    // Add other examples
    const examples = [_]struct { name: []const u8, path: []const u8, lib: []const u8 }{
        .{ .name = "example_tap_libev", .path = "examples/main_tap_libev.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev", .path = "examples/main_af_packet_libev.zig", .lib = "ev" },
        .{ .name = "example_af_xdp_libuv", .path = "examples/main_af_xdp_libuv.zig", .lib = "uv" },
        .{ .name = "example_af_xdp_libev", .path = "examples/main_af_xdp_libev.zig", .lib = "ev" },
    };

    for (examples) |ex| {
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("ustack", ustack_mod);
        exe.linkLibrary(lib);
        exe.linkLibC();

        exe.linkSystemLibrary(ex.lib);
        if (std.mem.eql(u8, ex.name, "example_tap_libev")) {
            exe.addCSourceFile(.{ .file = b.path("examples/wrapper.c"), .flags = &.{ "-I/usr/include", "-I/usr/local/include" } });
        }
        const install = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&install.step);
    }
}
