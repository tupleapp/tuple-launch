const std = @import("std");
const Builder = std.build.Builder;
const Step = std.build.Step;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const strip = b.option(bool, "strip", "strip binaries") orelse true;
    buildAnytype(b, "", mode, strip);
}

// This function allows this build to be used as apart of another build.zig.  Set `path_prefix`
// to the sub_path where this build.zig file exists (include trailing slash).
pub fn buildAnytype(b: *Builder, comptime path_prefix: []const u8, mode: std.builtin.Mode, strip: bool) void {
    const target = std.zig.CrossTarget.parse(.{
        .arch_os_abi = "x86_64-linux",
    }) catch unreachable;

    const signing_exe = b.addExecutable("signing", path_prefix ++ "signing.zig");
    signing_exe.single_threaded = true;
    signing_exe.override_dest_dir = .prefix;
    signing_exe.install();

    const path_prefix_no_ts = std.mem.trimRight(u8, path_prefix, "/");

    const LaunchExeVariant = enum { dev, customer };
    inline for (std.meta.fields(LaunchExeVariant)) |field| {
        const variant = @intToEnum(LaunchExeVariant, field.value);
        const suffix = switch (variant) { .dev => "-dev", .customer => "" };
        const build_options = b.addOptions();
        build_options.addOption(LaunchExeVariant, "variant", variant);

        {
            const exe = b.addExecutable("tuple-launch" ++ suffix, path_prefix ++ "launch.zig");
            exe.addIncludePath(b.pathFromRoot(path_prefix_no_ts));
            exe.setBuildMode(mode);
            exe.setTarget(target);
            exe.single_threaded = true;
            exe.strip = strip;
            exe.override_dest_dir = .prefix;
            exe.install();
            exe.addOptions("build_options", build_options);
        }
        {
            const exe = b.addExecutable("tuple-flatpak-launch" ++ suffix, path_prefix ++ "flatpak-launch.zig");
            exe.addIncludePath(b.pathFromRoot(path_prefix_no_ts));
            exe.setBuildMode(mode);
            exe.setTarget(target);
            exe.single_threaded = true;
            exe.strip = strip;
            exe.override_dest_dir = .prefix;
            exe.install();
            exe.addOptions("build_options", build_options);

            const sign_exe = signing_exe.run();
            sign_exe.addArg("sign");
            sign_exe.addArg(b.pathFromRoot(path_prefix ++ "tuple_dev_ed25519"));
            sign_exe.addArtifactArg(exe);
            b.getInstallStep().dependOn(&sign_exe.step);
        }
    }
}
