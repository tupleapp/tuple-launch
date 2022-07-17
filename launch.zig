const build_options = @import("build_options");
const std = @import("std");
const os = std.os;

const c = @cImport({
    @cInclude("LaunchProtocol.h");
});

const Signer = std.crypto.sign.Ed25519;
const Hasher = std.crypto.hash.Blake3;

const findexe = @import("findexe.zig");
const Log = @import("tuplelog.zig").Log("tuple-launch");
const log = Log.log;

const FlatpakInstallKind = enum { system, user };

var global_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

fn getCmdlineOption(i: *usize) [*:0]u8 {
    i.* += 1;
    if (i.* >= os.argv.len) {
        log.err(@src(), "command-line option '{s}' requires an argument", .{os.argv[i.*-1]});
        os.exit(0xff);
    }
    return os.argv[i.*];
}

const LaunchExec = switch (build_options.variant) {
    .dev => struct { opt_argv_offset: ?usize = null },
    .customer => struct {},
};

pub fn main() !void {
    log.info(@src(), "tuple-launch started", .{});
    try Log.initSigpipeHandler();

    var opt = struct {
        flatpak_id: ?[*:0]const u8 = null,
        flatpak_install_kind: ?FlatpakInstallKind = null,
    }{};
    var launch_exec: LaunchExec = .{};

    {
        var arg_index: usize = 1;
        argv_loop: while (arg_index < os.argv.len) : (arg_index += 1) {
            const arg = std.mem.span(os.argv[arg_index]);
            if (std.mem.eql(u8, arg, "--launch-vector-pipe")) {
                const str = std.mem.span(getCmdlineOption(&arg_index));
                Log.vector_pipe_fd = std.fmt.parseInt(os.fd_t, str, 10) catch |err| {
                    log.err(@src(), "--launch-vector-pipe '{s}' is not an fd number: {s}", .{str, @errorName(err)});
                    os.exit(0xff);
                };
                log.info(@src(), "vector-pipe set to {s}", .{str});
            } else if (std.mem.eql(u8, arg, "--flatpak-id")) {
                opt.flatpak_id = getCmdlineOption(&arg_index);
            } else if (std.mem.eql(u8, arg, "--flatpak-system")) {
                opt.flatpak_install_kind = .system;
            } else if (std.mem.eql(u8, arg, "--flatpak-user")) {
                opt.flatpak_install_kind = .user;
            } else switch (build_options.variant) {
                .customer => {},
                .dev => {
                    // The --launch-exec option allows the caller to specify the tuple-flatpak-launch
                    // binary location, along with any number of programs/arguments before, i.e.
                    //     --launch-exec tuple-flatpak-launch
                    //     --launch-exec strace -ff tuple-flatpak-launch
                    //     --launch-exec gdb -ex tuple-flatpak-launch
                    // Everything after --launch-exec is assumed to be apart of this option.
                    if (std.mem.eql(u8, arg, "--launch-exec")) {
                        if (arg_index + 1 >= os.argv.len) {
                            log.err(@src(), "--launch-exec requires 1 ore more arguments", .{});
                            os.exit(0xff);
                        }
                        launch_exec = .{ .opt_argv_offset = arg_index + 1 };
                        break :argv_loop;
                    }
                },
            }
        }
    }

    const flatpak_id = std.mem.span(opt.flatpak_id orelse {
        log.err(@src(), "missing cmdline option '--flatpak-id'", .{});
        os.exit(0xff);
    });

    const flatpak_install_kind = opt.flatpak_install_kind orelse {
        log.err(@src(), "need either --flatpak-system or --flatpak-user", .{});
        os.exit(0xff);
    };

    // only allow our known application ids
    switch (build_options.variant) {
        .dev => {},
        .customer => {
            if (!std.mem.eql(u8, flatpak_id, "app.tuple.app") and !std.mem.eql(u8, flatpak_id, "app.tuple.staging")) {
                log.err(@src(), "unauthorized flatpak app id '{s}'", .{flatpak_id});
                os.exit(0xff);
            }
        },
    }

    const flatpak_exe = (try findExe("flatpak")) orelse {
        log.err(@src(), "unable to find the 'flatpak' executable in PATH", .{});
        os.exit(0xff);
    };

    const tuple_flatpak_launch_exe = try getTupleFlatpakLaunchExe(flatpak_id, flatpak_install_kind, flatpak_exe, launch_exec);
    const signature = readSigFile(tuple_flatpak_launch_exe) catch |err| switch (err) {
        error.FileNotFound => {
            log.err(@src(), "'{s}.sig' not found", .{tuple_flatpak_launch_exe});
            os.exit(c.EXIT_CODE_INVALID_SIGNATURE);
        },
        else => |e| return e,
    };

    const memfd = try os.memfd_createZ(
        tuple_flatpak_launch_exe,
        os.linux.MFD.ALLOW_SEALING,
    );

    log.info(@src(), "loading tuple-flatpak-launch into memory...", .{});
    const exe_size = blk: {
        var file = try std.fs.cwd().openFile(tuple_flatpak_launch_exe, .{});
        defer file.close();
        const size = try file.getEndPos();
        log.info(@src(), "file size is {} bytes", .{size});

        var offset: u64 = 0;
        while (offset < size) {
            const send_result = os.linux.sendfile(memfd, file.handle, @ptrCast(*i64, &offset), size - offset);
            switch (os.errno(send_result)) {
                .SUCCESS => {},
                else => |errno| {
                    log.err(@src(), "sendfile for flatpak exe failed (offset={}, errno={})", .{offset, errno});
                    os.exit(0xff);
                },
            }
            log.info(@src(), "wrote {} bytes", .{send_result});
            offset += send_result;
        }
        break :blk size;
    };

    // Seal the memfd to prevent it from being modified
    _ = try os.fcntl(
        memfd,
        linuxext.F.ADD_SEALS,
        linuxext.F.SEAL_SEAL |
            linuxext.F.SEAL_SHRINK |
            linuxext.F.SEAL_GROW |
            linuxext.F.SEAL_WRITE,
    );

    log.info(@src(), "verifying the exe...", .{});
    var hash: [Hasher.digest_length]u8 = undefined;
    {
        const mem = try os.mmap(null, exe_size, os.PROT.READ, os.MAP.PRIVATE, memfd, 0);
        defer os.munmap(mem);
        var hasher = Hasher.init(.{});
        hasher.update(mem);
        hasher.final(&hash);
    }

    // TODO: use the release public key in the customer variant
    Signer.verify(signature, &hash, tuple_dev_ed25519_pub) catch |err| switch (err) {
        error.SignatureVerificationFailed => {
            log.err(@src(), "verification failed, tuple-flatpak-launch exe corrupted", .{});
            os.exit(c.EXIT_CODE_INVALID_SIGNATURE);
        },
        else => |e| return e,
    };

    const new_args = try std.heap.page_allocator.alloc(?[*:0]const u8, os.argv.len + 1);
    var new_args_len: usize = 0;

    const os_argv_limit = blk: {
        switch (build_options.variant) {
            .dev => if (launch_exec.opt_argv_offset) |argv_offset| {
                const prefix_args = os.argv[argv_offset..os.argv.len - 1];
                for (prefix_args) |arg| {
                    new_args[new_args_len] = arg;
                    new_args_len += 1;
                }
                if (prefix_args.len > 0) {
                    const exe = std.mem.span(prefix_args[0]);
                    new_args[0] = (try findExe(exe)) orelse {
                        log.err(@src(), "unable to find executable '{s}' in PATH", .{exe});
                        os.exit(0xff);
                    };
                }
                break :blk argv_offset - 1;
            },
            .customer => {},
        }
        break :blk os.argv.len;
    };
    new_args[new_args_len] = tuple_flatpak_launch_exe.ptr;
    new_args_len += 1;
    {
        var i: usize = 1;
        while (i < os_argv_limit) : (i += 1) {
            new_args[new_args_len] = os.argv[i];
            new_args_len += 1;
        }
    }
    new_args[new_args_len] = null;
    log.info(@src(), "exec '{s}' with {} arguments", .{tuple_flatpak_launch_exe, new_args_len});
    if (false) {
        for (new_args[0 .. new_args_len]) |new_arg, i| {
            log.info(@src(), "[{}] '{s}'", .{i, new_arg});
        }
    }
    const execve_err = blk: {
        switch (build_options.variant) {
            .dev => if (launch_exec.opt_argv_offset) |_| break :blk os.errno(os.linux.execve(
                new_args[0].?,
                std.meta.assumeSentinel(new_args.ptr, null),
                envp(),
            )),
            .customer => {},
        }
        break :blk os.errno(linuxext.execveat(
            memfd,
            "",
            std.meta.assumeSentinel(new_args.ptr, null),
            envp(),
            os.linux.AT.EMPTY_PATH,
        ));
    };
    log.err(@src(), "execve '{s}' failed with E{s}", .{tuple_flatpak_launch_exe, @tagName(execve_err)});
    os.exit(0xff);
}

const launch_suffix = switch (build_options.variant) {
    .dev => "-dev",
    .customer => "",
};

pub fn getTupleFlatpakLaunchExe(
    flatpak_id: []const u8,
    flatpak_install_kind: FlatpakInstallKind,
    flatpak_exe: [:0]const u8,
    launch_exec: LaunchExec,
) ![:0]const u8 {
    switch (build_options.variant) {
        .dev => if (launch_exec.opt_argv_offset) |_| return std.mem.span(os.argv[os.argv.len - 1]),
        .customer => {},
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var args = std.ArrayListUnmanaged([]const u8) { };
    defer args.deinit(arena.allocator());
    try args.append(arena.allocator(), flatpak_exe);
    try args.append(arena.allocator(), "info");
    try args.append(arena.allocator(), switch (flatpak_install_kind) {
        .system => "--system",
        .user => "--user",
    });
    try args.append(arena.allocator(), "--show-location");
    try args.append(arena.allocator(), flatpak_id);

    if (false) {
        log.info(@src(), "launching flatpak info...", .{});
        for (args.items) |arg, i| {
            log.info(@src(), "[{}] '{s}'", .{i, arg});
        }
    }

    // TODO: maybe use less abstraction here to be more efficient?
    const result = try std.ChildProcess.exec(.{
        .allocator = arena.allocator(),
        .argv = args.items,
    });
    if (result.stderr.len > 0) {
        log.err(@src(), "flatpak info --show-location stderr: '{s}'", .{result.stderr});
    }
    switch (result.term) {
        .Exited => |code| {
            if (code != 0) {
                log.err(@src(), "flatpak info --show-location failed with exit code {} (stdout='{s}')", .{code, result.stdout});
                os.exit(0xff);
            }
        },
        else => {
            log.err(@src(), "flatpak info --show-location terminated with {} (stdout='{s}')", .{result.term, result.stdout});
            os.exit(0xff);
        },
    }
    const location = std.mem.trimRight(u8, result.stdout, "\n\r ");
    log.debug(@src(), "flatpak location is '{s}'", .{location});
    return try std.fmt.allocPrintZ(global_arena.allocator(), "{s}/files/bin/tuple-flatpak-launch" ++ launch_suffix, .{location});
}

const tuple_dev_ed25519_pub = blk: {
    const pub_hex = @embedFile("tuple_dev_ed25519.pub");
    var buf: [Signer.public_length]u8 = undefined;
    const len = (std.fmt.hexToBytes(&buf, pub_hex) catch @panic("pub keyfile contained non-hex digits")).len;
    std.debug.assert(len == buf.len);
    break :blk buf;
};

fn openSigFile(content_filename: []const u8) !std.fs.File {
    var sig_filename_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const sig_filename = try std.fmt.bufPrintZ(&sig_filename_buf, "{s}.sig", .{ content_filename });
    return std.fs.cwd().openFileZ(sig_filename, .{});
}

fn readSigFile(content_filename: []const u8) ![Signer.signature_length]u8 {
    var file = try openSigFile(content_filename);
    defer file.close();

    const hex_len = Signer.signature_length * 2;
    var content: [hex_len]u8 = undefined;
    {
        const read_len = try file.readAll(&content);
        if (read_len != hex_len) {
            log.err(@src(), "expected '{s}.sig' to be {} bytes but is {}", .{content_filename, hex_len, read_len});
            std.os.exit(0xff);
        }
    }
    var bytes: [Signer.signature_length]u8 = undefined;
    const bytes_len = (try std.fmt.hexToBytes(&bytes, &content)).len;
    if (bytes.len != bytes_len) {
        log.err(@src(), "'{s}.sig' contained invalid hex characters", .{content_filename});
        std.os.exit(0xff);
    }
    return bytes;

}

fn envp() [*:null]const ?[*:0]const u8 {
    return @ptrCast([*:null]const ?[*:0]const u8, os.environ);
}

fn findExe(basename: []const u8) !?[:0]u8 {
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    if (try findexe.findExeBuf(basename, &path_buf)) |len| {
        return try global_arena.allocator().dupeZ(u8, path_buf[0 ..len]);
    }
    return null;
}

// TODO: all this should be in std
const linuxext = struct {
    pub const F = struct {
        pub const ADD_SEALS = 1033;
        pub const SEAL_SEAL   = (1 << 0);
        pub const SEAL_SHRINK = (1 << 1);
        pub const SEAL_GROW   = (1 << 2);
        pub const SEAL_WRITE  = (1 << 3);
    };
    pub fn execveat(dirfd: i32, path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, e: [*:null]const ?[*:0]const u8, flags: u32) usize {
        return os.linux.syscall5(.execveat, @bitCast(usize, @as(isize, dirfd)), @ptrToInt(path), @ptrToInt(argv), @ptrToInt(e), @as(usize, flags));
    }
};
