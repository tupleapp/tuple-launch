const build_options = @import("build_options");
const std = @import("std");
const os = std.os;

const Cmsghdr = @import("cmsghdr.zig").Cmsghdr;

const c = @cImport({
    @cInclude("LaunchProtocol.h");
});

const findexe = @import("findexe.zig");
const Log = @import("tuplelog.zig").Log("tuple-flatpak-launch");
const log = Log.log;

const FlatpakInstallKind = enum { system, user };

const LaunchExec = switch (build_options.variant) {
    .dev => struct { opt_args: ?[][*:0] u8 = null },
    .customer => struct {},
};

fn getCmdlineOption(i: *usize) [*:0]u8 {
    i.* += 1;
    if (i.* >= os.argv.len) {
        log.err(@src(), "command-line option '{s}' requires an argument", .{os.argv[i.*-1]});
        os.exit(0xff);
    }
    return os.argv[i.*];
}

pub fn main() !void {
    log.info(@src(), "tuple-flatpak-launch started", .{});
    try Log.initSigpipeHandler();

    var opt: struct {
        flatpak_install_kind: ?FlatpakInstallKind = null,
        flatpak_id: ?[*:0]const u8 = null,
    } = .{};
    var launch_exec: LaunchExec = .{};

    {
        var arg_index: usize = 1;
        var new_os_argv_len: usize = 1;
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
            } else {
                switch (build_options.variant) {
                    .customer => {},
                    .dev => {
                        if (std.mem.eql(u8, arg, "--flatpak-launch-exec")) {
                            launch_exec = .{ .opt_args = os.argv.ptr[arg_index + 1 .. os.argv.len] };
                            break :argv_loop;
                        }
                    },
                }
                os.argv[new_os_argv_len] = arg.ptr;
                new_os_argv_len += 1;
            }
        }
        os.argv = os.argv[0 .. new_os_argv_len];
    }

    const flatpak_id = opt.flatpak_id orelse {
        log.err(@src(), "missing --flatpak-id cmdline argument", .{});
        os.exit(0xff);
    };
    const flatpak_install_kind = opt.flatpak_install_kind orelse {
        log.err(@src(), "need either --flatpak-system or --flatpak-user", .{});
        os.exit(0xff);
    };

    const uids = getUids();
    const tuple_proc = try launchTuple(flatpak_id, flatpak_install_kind, launch_exec, uids);
    log.info(@src(), "started tuple (pid={})", .{tuple_proc.pid});

    // TODO: de-escalate
    {
        // TODO: is there a full-proof way we could verify that once we de-escalate we'll still have
        //       access to /dev/input/event*?
    }

    const epoll_fd = try os.epoll_create1(os.linux.EPOLL.CLOEXEC);

    // looks like we may not need to listen for SIGCHLD because the socketpair will get
    // shutdown instead.
    //const signal_fd = try createSignalfd();
    //try epollAdd(epoll_fd, os.linux.EPOLL.CTL_ADD, signal_fd, os.linux.EPOLL.IN, .signal);

    try epollAdd(epoll_fd, os.linux.EPOLL.CTL_ADD, tuple_proc.sock, os.linux.EPOLL.IN, .sock);

    while (true) {
        var events: [10]os.linux.epoll_event = undefined;
        const event_count = os.epoll_wait(epoll_fd, &events, -1);
        for (events[0..event_count]) |*event| {
            switch (@intToEnum(EpollHandler, event.data.@"u32")) {
                .sock => try onSock(tuple_proc.sock),
            }
        }
    }
}

const EpollHandler = enum {
    //signal,
    sock,
};
fn epollAdd(epoll_fd: os.fd_t, op: u32, fd: os.fd_t, events: u32, handler: EpollHandler) !void {
    var event = os.linux.epoll_event{
        .events = events,
        .data = .{ .@"u32" = @enumToInt(handler) },
    };
    return os.epoll_ctl(epoll_fd, op, fd, &event);
}

fn onSock(sock: os.socket_t) !void {
    var msg_buf: [c.LAUNCH_REQUEST_MAX]u8 = undefined;
    const msg_len = os.read(sock, &msg_buf) catch |err| switch (err) {
        error.WouldBlock => return,
        else => |e| return e,
    };
    if (msg_len == 0) {
        log.info(@src(), "tuple socketpair shutdown, exiting...", .{});
        os.exit(0);
    }

    const msg = msg_buf[0..msg_len];
    var it = std.mem.tokenize(u8, msg, " ");
    const name = it.next() orelse {
        sendMsgCt(sock, "error empty message");
        return;
    };
    if (std.mem.eql(u8, name, "ping")) {
        sendMsgCt(sock, "pong");
    } else if (std.mem.eql(u8, name, "grab-mice")) {
        if (it.next()) |_| {
            sendMsgCt(sock, "error too many arguments to grab-mice command");
            return;
        }
        try grabMice(sock);
    } else if (std.mem.eql(u8, name, "setids")) {
        const team_id_string = it.next() orelse {
            sendMsgCt(sock, "error setids command missing team_id");
            return;
        };
        const user_id_string = it.next() orelse {
            sendMsgCt(sock, "error setids command missing user_id");
            return;
        };
        const team_id = std.fmt.parseInt(i64, team_id_string, 10) catch {
            sendMsgCt(sock, "error setids team id is invalid");
            return;
        };
        const user_id = std.fmt.parseInt(i64, user_id_string, 10) catch {
            sendMsgCt(sock, "error setids user id is invalid");
            return;
        };
        if (it.next()) |_| {
            sendMsgCt(sock, "error too many arguments to setids command");
            return;
        }
        Log.team_id = team_id;
        Log.user_id = user_id;
        log.info(@src(), "team/user ids set", .{});
        sendMsgCt(sock, "ok");
    } else {
        sendMsgFmt(sock, "error unknown command '{s}'", .{name});
    }
}

fn rdevMajor(rdev: os.dev_t) u32 {
    return @intCast(u32, ((rdev >> 32) & 0xfffff000) | ((rdev >> 8) & 0x00000fff));
}
fn rdevMinor(rdev: os.dev_t) u32 {
    return @intCast(u32, ((rdev >> 12) & 0xffffff00) | (rdev & 0x000000ff));
}

fn grabMice(sock: os.socket_t) !void {
    var dir = try std.fs.openDirAbsolute("/dev/input", .{ .iterate = true });
    defer dir.close();

    var dir_it = dir.iterate();
    while (try dir_it.next()) |entry| {
        if (entry.kind != .CharacterDevice) continue;
        const stat = os.fstatat(dir.fd, entry.name, 0) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };

        const major = rdevMajor(stat.rdev);
        const minor = rdevMinor(stat.rdev);

        if (major != 13) continue; // not an evdev device
        const minor_in_range = (minor >= 64 and minor <= 95) or (minor >= 256);
        if (!minor_in_range) continue; // not an evdev device
        if (!try isMouse(entry.name, major, minor)) continue;

        var open_result = dir.openFile(entry.name, .{}) catch |err| {
            sendMsgFmt(sock, "error open '/dev/input/{s}' failed with {s}", .{entry.name, @errorName(err)});
            return;
        };
        // TODO: is it ok to close this right after sending it? Seems to be
        defer open_result.close();
        sendFd(sock, "fd", open_result.handle);
    }
    sendMsgCt(sock, "done");
}

fn isMouse(entry_name: []const u8, major: u32, minor: u32) !bool {
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/sys/dev/char/{}:{}/device", .{ major, minor }) catch unreachable;
    var dir = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.warn("device '/dev/input/{s}' has no sysfs entry at '{s}', ignoring", .{entry_name, path});
            return false; // ignore
        },
        else => |e| return e,
    };
    defer dir.close();
    var rel_file = dir.openFile("capabilities/rel", .{}) catch |err| switch (err) {
        error.FileNotFound => return false, // not a mouse
        else => |e| return e,
    };
    defer rel_file.close();
    const max_hex_string = 8;
    var hex_buf: [max_hex_string+1]u8 = undefined;
    const len = try rel_file.read(&hex_buf);
    if (len == 0 or len > max_hex_string) {
        std.log.err("read '{s}' unexpectedly returned {}", .{path, len});
        return error.UnexpectedFileContent;
    }
    const hex = std.mem.trimRight(u8, hex_buf[0 .. len], "\n");
    const rel_bits = std.fmt.parseInt(u64, hex, 16) catch |err| {
        std.log.err("read '{s}' returned invalid hex '{}': {s}", .{path, std.zig.fmtEscapes(hex), @errorName(err)});
        return error.UnexpectedFileContent;
    };
    const rel_x = rel_bits & (1 << REL_X);
    const rel_y = rel_bits & (1 << REL_Y);
    if ((rel_x == 0) and (rel_y == 0)) return false; // not a mouse

    return true; // is a mouse
}

const REL_X = 0;
const REL_Y = 1;

const SCM_RIGHTS = 1;

fn sendFd(sock: os.socket_t, msg: []const u8, fd: os.fd_t) void {
    var iov = [_]os.iovec_const{
        .{
            .iov_base = msg.ptr,
            .iov_len = msg.len,
        },
    };
    var cmsg = Cmsghdr(os.fd_t).init(.{
        .level = os.SOL.SOCKET,
        .@"type" = SCM_RIGHTS,
        .data = fd,
    });
    const len = os.sendmsg(sock, .{
        .name = undefined,
        .namelen = 0,
        .iov = &iov,
        .iovlen = iov.len,
        .control = &cmsg,
        .controllen = @sizeOf(@TypeOf(cmsg)),
        .flags = 0,
        }, 0) catch |err| {
        // this'll probably fail too, but no harm in trying
        sendMsgFmt(sock, "error sendmsg failed with {s}", .{@errorName(err)});
        return;
    };
    if (len != 2) {
        // we don't have much choice but to exit here
        log.err(@src(), "expected sendmsg to return 2 but got {}", .{len});
        os.exit(0xff);
    }
}

fn sendMsgCt(sock: os.socket_t, comptime msg: []const u8) void {
    sendMsg(sock, msg);
}
fn sendMsgFmt(sock: os.socket_t, comptime fmt: []const u8, args: anytype) void {
    var msg_buf: [c.LAUNCH_REPLY_MAX]u8 = undefined;
    const send_msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => {
            log.err(@src(), "unable to send message, it's too big: fmt={s}", .{fmt});
            os.exit(0xff);
        },
    };
    sendMsg(sock, send_msg);
}
fn sendMsg(sock: os.socket_t, msg: []const u8) void {
    const sent = os.write(sock, msg) catch |err| {
        log.err(@src(), "failed to send {}-byte message with {s}", .{msg.len, @errorName(err)});
        os.exit(0xff); // not much to do except exit with a non-zero exit code
    };
    // the socket should be SOCK_SEQPACKET so should either be sending the whole message or nothing
    std.debug.assert(sent == msg.len);
}

const TupleProc = struct {
    pid: os.pid_t,
    sock: os.socket_t,
};
fn launchTuple(
    flatpak_id: [*:0]const u8,
    flatpak_install_kind: FlatpakInstallKind,
    launch_exec: LaunchExec,
    uids: Uids,
) !TupleProc {
    var socks: [2]os.fd_t = undefined;
    switch (os.errno(os.linux.socketpair(os.linux.AF.UNIX, os.linux.SOCK.SEQPACKET, 0, &socks))) {
        .SUCCESS => {},
        else => |errno| {
            log.err(@src(), "failed to create unix socketpair, errno={}", .{errno});
            os.exit(0xff);
        },
    }

    var sock_fd_str_buf: [30]u8 = undefined;
    const sock_fd_str = try std.fmt.bufPrintZ(&sock_fd_str_buf, "{}", .{socks[1]});

    const pid = try os.fork();
    if (pid != 0) {
        os.close(socks[1]); // close socket meant for tuple
        return TupleProc{ .pid = pid, .sock = socks[0] };
    }

    os.close(socks[0]); // close the socket meant for tuple-flatpak-launch

    if (uids.isSuid()) {
        const change_to = if (uids.saved != uids.effective) uids.saved else uids.real;
        log.info(@src(), "de-escalating to uid {}", .{change_to});
        switch (os.errno(os.linux.setresuid(change_to, change_to, change_to))) {
            .SUCCESS => {},
            else => |errno| {
                log.err(@src(), "failed to set real/effective/saved uids to {} (errno={}, current={})", .{change_to, errno, uids});
                os.exit(0xff);
            },
        }
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const al = arena.allocator();
    var args = std.ArrayListUnmanaged(?[*:0]const u8){ };

    const use_flatpak_run = blk: {
        switch (build_options.variant) {
            .dev => if (launch_exec.opt_args) |exec_args| {
                for (exec_args) |arg| {
                    try args.append(al, arg);
                }
                break :blk false;
            },
            .customer => {},
        }
        break :blk true;
    };

    if (use_flatpak_run) {
        const flatpak_exe = (try findExe(arena.allocator(), "flatpak")) orelse {
            log.err(@src(), "unable to find the 'flatpak' executable in PATH", .{});
            os.exit(0xff);
        };
        try args.append(al, flatpak_exe);
        try args.append(al, "run");
        try args.append(al, switch (flatpak_install_kind) {
            .system => "--system",
            .user => "--user",
        });
        try args.append(al, flatpak_id);
    }
    for (os.argv.ptr[1..os.argv.len]) |arg| {
        try args.append(al, arg);
    }
    try args.append(al, "--launch-sock");
    try args.append(al, sock_fd_str);
    try args.append(al, null);
    const actual_arg_count = args.items.len - 1;
    log.info(@src(), "spawning tuple with {} args", .{actual_arg_count});
    if (false) {
        for (args.items[0 .. actual_arg_count]) |arg, i| {
            log.info(@src(), "[{}] '{s}'", .{i, arg});
        }
    }
    const err = os.execveZ(args.items[0].?, std.meta.assumeSentinel(args.items, null), envp());
    log.err(@src(), "execve for next tuple failed with {s}", .{@errorName(err)});
    os.exit(0xff);
}

fn envp() [*:null]const ?[*:0]const u8 {
    return @ptrCast([*:null]const ?[*:0]const u8, os.environ);
}

const Uids = struct {
    real: os.uid_t,
    effective: os.uid_t,
    saved: os.uid_t,

    pub fn isSuid(self: Uids) bool {
        return self.real != self.effective or self.real != self.saved;
    }
};

fn getUids() Uids {
    var uids: Uids = undefined;
    switch (os.errno(os.linux.getresuid(&uids.real, &uids.effective, &uids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            log.err(@src(), "getresuid failed, errno={}", .{errno});
            os.exit(0xff);
        },
    }
    return uids;
}

fn findExe(allocator: std.mem.Allocator, basename: []const u8) !?[:0]u8 {
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    if (try findexe.findExeBuf(basename, &path_buf)) |len| {
        return try allocator.dupeZ(u8, path_buf[0 ..len]);
    }
    return null;
}
