const std = @import("std");

const stdout = std.io.getStdOut().writer();

pub fn JsonStringWriter(comptime UnderlyingWriter: type) type {
    return struct {
        underlying_writer: UnderlyingWriter,
        const Self = @This();
        pub const Error = UnderlyingWriter.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            try outputJsonStringPartial(bytes, .{}, self.underlying_writer);
            return bytes.len;
        }
    };
}

pub fn Log(comptime role: []const u8) type {
    return struct {
        pub fn initSigpipeHandler() !void {
            const act = std.os.Sigaction{
                .handler = .{ .sigaction = std.os.SIG.IGN },
                .mask = std.os.empty_sigset,
                .flags = std.os.SA.SIGINFO,
            };
            try std.os.sigaction(std.os.SIG.PIPE, &act, null);
        }

        pub var vector_pipe_fd: std.os.fd_t = -1;
        pub var team_id: i64 = -1;
        pub var user_id: i64 = -1;

        pub const log = struct {
            pub fn err(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
                @setCold(true);
                logCommon(src, format, args, .err);
            }
            pub fn warn(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
                logCommon(src, format, args, .warn);
            }
            pub fn info(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
                logCommon(src, format, args, .info);
            }
            pub fn debug(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
                logCommon(src, format, args, .debug);
            }
        };

        pub fn logCommon(
            comptime src: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
            comptime level: std.log.Level,
        ) void {
            logToStdout(format, args, level) catch |err|
                std.debug.panic("log to stdout failed with {s}", .{@errorName(err)});
            if (vector_pipe_fd != -1) {
                logToVector(src, format, args, level) catch |err| {
                    // we'll leave the pipe fd open in case this is the first tuple-launch process
                    // and we pass the vector pipe fd to the next launch process.  It will get the same
                    // failure but at least the fd number will be valid. Leaving it open doesn't hurt anything.
                    //std.os.close(vector_pipe_fd);
                    vector_pipe_fd = -1;
                    logToStdout("logToVector failed with {s}, closing the vector pipe!", .{@errorName(err)}, .err)
                        catch |err2| std.debug.panic("can't log to vector nor stdout with {s}", .{@errorName(err2)});
                };
            }
        }

        fn logToVector(
            comptime src: std.builtin.SourceLocation,
            comptime format: []const u8,
            args: anytype,
            comptime level: std.log.Level,
        ) !void {
            std.debug.assert(vector_pipe_fd != -1);
            const vector_level = switch (level) {
                .err => "error",
                .warn => "warning",
                .info => "info",
                .debug => "debug",
            };
            var vector_pipe_writer = std.fs.File{ .handle = vector_pipe_fd };
            const BufferedWriter = std.io.BufferedWriter(400, @TypeOf(vector_pipe_writer.writer()));
            var buffered = BufferedWriter{
                .unbuffered_writer = vector_pipe_writer.writer(),
            };
            try buffered.writer().writeAll("{\"message\": \"");
            {
                var json_writer = JsonStringWriter(BufferedWriter.Writer) { .underlying_writer = buffered.writer() };
                try std.fmt.format(json_writer.writer(), format, args);
            }
            const static_fields = "\""
                ++ ", \"level\": \"" ++ vector_level ++ "\""
                ++ ", \"fields\": { \"platform\": \"linux\""
            ;
            try buffered.writer().writeAll(static_fields);
            const filename = comptime std.fs.path.basename(src.file);
            try buffered.writer().print(
                ", \"team_id\": {}, \"user_id\": {}" ++
                ", \"source\": {{ \"filename\": \"{s}\", \"line\": {}, \"func\": \"{s}\" }} }} }}\n", .{
                    team_id, user_id, filename, src.line, src.fn_name});
            try buffered.flush();
        }

        fn logToStdout(
            comptime format: []const u8,
            args: anytype,
            comptime level: std.log.Level,
        ) !void {
            var buffered = std.io.BufferedWriter(400, @TypeOf(stdout)){
                .unbuffered_writer = stdout,
            };
            var timespec = std.os.timespec{
                .tv_sec = 0,
                .tv_nsec = 0,
            };
            std.os.clock_gettime(std.os.CLOCK.REALTIME, &timespec) catch {
                timespec.tv_sec = 0;
            };
            const day_time = std.time.epoch.DaySeconds{
                .secs = std.math.comptimeMod(timespec.tv_sec, std.time.epoch.secs_per_day),
            };
            const millis = @floatToInt(u16, @intToFloat(f32, timespec.tv_nsec) / std.time.ns_per_ms);
            try buffered.writer().print(
                "[UTC:{:0>2}:{:0>2}:{:0>2}:{:0>3}] [" ++ level.asText() ++ "] [" ++ role ++ "] ",
                .{
                    day_time.getHoursIntoDay(),
                    day_time.getMinutesIntoHour(),
                    day_time.getSecondsIntoMinute(),
                    millis,
                },
            );
            try buffered.writer().print(format ++ "\n", args);
            try buffered.flush();
        }
    };
}

// NOTE the following was copied from std, this PR should expose it so we can remove our copy
//     https://github.com/ziglang/zig/pull/11972
fn outputUnicodeEscape(
    codepoint: u21,
    out_stream: anytype,
) !void {
    if (codepoint <= 0xFFFF) {
        // If the character is in the Basic Multilingual Plane (U+0000 through U+FFFF),
        // then it may be represented as a six-character sequence: a reverse solidus, followed
        // by the lowercase letter u, followed by four hexadecimal digits that encode the character's code point.
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(codepoint, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    } else {
        std.debug.assert(codepoint <= 0x10FFFF);
        // To escape an extended character that is not in the Basic Multilingual Plane,
        // the character is represented as a 12-character sequence, encoding the UTF-16 surrogate pair.
        const high = @intCast(u16, (codepoint - 0x10000) >> 10) + 0xD800;
        const low = @intCast(u16, codepoint & 0x3FF) + 0xDC00;
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(high, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(low, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    }
}
fn outputJsonStringPartial(value: []const u8, options: std.json.StringifyOptions, writer: anytype) !void {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        switch (value[i]) {
            // normal ascii character
            0x20...0x21, 0x23...0x2E, 0x30...0x5B, 0x5D...0x7F => |c| try writer.writeByte(c),
            // only 2 characters that *must* be escaped
            '\\' => try writer.writeAll("\\\\"),
            '\"' => try writer.writeAll("\\\""),
            // solidus is optional to escape
            '/' => {
                if (options.string.String.escape_solidus) {
                    try writer.writeAll("\\/");
                } else {
                    try writer.writeByte('/');
                }
            },
            // control characters with short escapes
            // TODO: option to switch between unicode and 'short' forms?
            0x8 => try writer.writeAll("\\b"),
            0xC => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                const ulen = std.unicode.utf8ByteSequenceLength(value[i]) catch unreachable;
                // control characters (only things left with 1 byte length) should always be printed as unicode escapes
                if (ulen == 1 or options.string.String.escape_unicode) {
                    const codepoint = std.unicode.utf8Decode(value[i .. i + ulen]) catch unreachable;
                    try outputUnicodeEscape(codepoint, writer);
                } else {
                    try writer.writeAll(value[i .. i + ulen]);
                }
                i += ulen - 1;
            },
        }
    }
}
