const std = @import("std");
const Builder = std.build.Builder;
const Step = std.build.Step;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const strip = b.option(bool, "strip", "strip binaries") orelse true;

    const path_prefix = "";
    const signing_exe = addSigningExe(b, path_prefix);
    const dev_signing = Signing{
        .exe = signing_exe,
        .key_filename = b.pathFromRoot("tuple_dev_ed25519"),
    };
    _ = addLaunchExes(b, path_prefix, mode, .customer, .{ .pubkey_filepath = "tuple_dev_ed25519.pub", .strip = strip, .exe_suffix = ""    , .signing = null });
    _ = addLaunchExes(b, path_prefix, mode, .dev     , .{ .pubkey_filepath = "tuple_dev_ed25519.pub", .strip = strip, .exe_suffix = "-dev", .signing = dev_signing });
}

pub const SigningExe = struct {
    exe: *std.build.LibExeObjStep,
};

fn concat(b: *Builder, left: []const u8, right: []const u8) []u8 {
    return std.mem.concat(b.allocator, u8, &.{left, right}) catch unreachable;
}

pub fn addSigningExe(b: *Builder, comptime path_prefix: []const u8) SigningExe {
    const exe = b.addExecutable("signing", path_prefix ++ "signing.zig");
    exe.single_threaded = true;
    exe.override_dest_dir = .prefix;
    exe.install();
    return SigningExe{ .exe = exe };
}

pub const LaunchExeVariant = enum { dev, customer };

pub const LaunchExes = struct {
    launch: *std.build.LibExeObjStep,
    flatpak_launch: *std.build.LibExeObjStep,
};

pub const Signing = struct {
    exe: SigningExe,
    key_filename: []const u8,
};

// This function allows this build to be used as apart of another build.zig.  Set `path_prefix`
// to the sub_path where this build.zig file exists (include trailing slash).
pub fn addLaunchExes(
    b: *Builder,
    path_prefix: []const u8,
    mode: std.builtin.Mode,
    variant: LaunchExeVariant,
    opt: struct {
        pubkey_filepath: []const u8,
        strip: bool,
        exe_suffix: []const u8,
        signing: ?Signing,
    },
) LaunchExes {
    const target = std.zig.CrossTarget.parse(.{
        .arch_os_abi = "x86_64-linux",
    }) catch unreachable;

    const path_prefix_no_ts = std.mem.trimRight(u8, path_prefix, "/");

    const build_options = b.addOptions();
    build_options.addOption(LaunchExeVariant, "variant", variant);
    build_options.addOption([]const u8, "pubkey_filepath", opt.pubkey_filepath);

    const launch_exe = blk: {
        const exe = b.addExecutable(concat(b, "tuple-launch", opt.exe_suffix), concat(b, path_prefix, "launch.zig"));
        exe.addIncludePath(b.pathFromRoot(path_prefix_no_ts));
        exe.setBuildMode(mode);
        exe.setTarget(target);
        exe.single_threaded = true;
        exe.strip = opt.strip;
        exe.override_dest_dir = .prefix;
        exe.install();
        exe.addOptions("build_options", build_options);
        break :blk exe;
    };
    const flatpak_launch_exe = blk: {
        const exe = b.addExecutable("tuple-flatpak-launch", concat(b, path_prefix, "flatpak-launch.zig"));
        exe.addIncludePath(b.pathFromRoot(path_prefix_no_ts));
        exe.setBuildMode(mode);
        exe.setTarget(target);
        exe.single_threaded = true;
        exe.strip = opt.strip;
        exe.override_dest_dir = .prefix;
        exe.install();
        exe.addOptions("build_options", build_options);

        if (opt.signing) |signing| {
            const sign_exe = signing.exe.exe.run();
            sign_exe.addArg("sign");
            sign_exe.addArg(signing.key_filename);
            sign_exe.addArtifactArg(exe);
            b.getInstallStep().dependOn(&sign_exe.step);
        }
        break :blk exe;
    };

    return .{ .launch = launch_exe, .flatpak_launch = flatpak_launch_exe };
}
