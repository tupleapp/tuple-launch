const std = @import("std");

/// TODO: move this to std

/// This definition enables the use of Zig types with a cmsghdr structure.
/// The oddity of this layout is that the data must be aligned to @sizeOf(usize)
/// rather than its natural alignment.
pub fn Cmsghdr(comptime T: type) type {
    const Header = extern struct {
        len: usize,
        level: c_int,
        @"type": c_int,
    };

    const data_align = @sizeOf(usize);
    const data_offset = std.mem.alignForward(@sizeOf(Header), data_align);

    return extern struct {
        const Self = @This();

        bytes: [data_offset + @sizeOf(T)]u8 align(@alignOf(Header)),

        pub fn init(args: struct {
            level: c_int,
            @"type": c_int,
            data: T,
        }) Self {
            var self: Self = undefined;
            self.headerPtr().* = .{
                .len = data_offset + @sizeOf(T),
                .level = args.level,
                .@"type" = args.@"type",
            };
            self.dataPtr().* = args.data;
            return self;
        }

        // TODO: include this version if we submit a PR to add this to std
        pub fn initNoData(args: struct {
            level: c_int,
            @"type": c_int,
        }) Self {
            var self: Self = undefined;
            self.headerPtr().* = .{
                .len = data_offset + @sizeOf(T),
                .level = args.level,
                .@"type" = args.@"type",
            };
            return self;
        }

        pub fn headerPtr(self: *Self) *Header {
            return @ptrCast(*Header, self);
        }
        pub fn dataPtr(self: *Self) *align(data_align) T {
            return @ptrCast(*T, self.bytes[data_offset..]);
        }
    };
}

test {
    std.testing.refAllDecls(Cmsghdr([3]std.os.fd_t));
}
