const std = @import("std");

pub fn findExeBuf(basename: []const u8, path_buf: *[std.fs.MAX_PATH_BYTES]u8) !?usize {
    const PATH = std.os.getenvZ("PATH") orelse "/bin:/usr/bin:/usr/local/bin";
    var it = std.mem.tokenize(u8, PATH, ":");
    while (it.next()) |search_path| {
        if (path_buf.len < search_path.len + basename.len + 1) continue;
        std.mem.copy(u8, path_buf, search_path);
        path_buf[search_path.len] = '/';
        std.mem.copy(u8, path_buf[search_path.len + 1 ..], basename);
        const path_len = search_path.len + basename.len + 1;
        path_buf[path_len] = 0;
        const full_path = path_buf[0..path_len :0];

        var stat: std.os.linux.Stat = undefined;
        switch (std.os.errno(std.os.linux.stat(full_path.ptr, &stat))) {
            .SUCCESS => {},
            else => continue,
        }
        return full_path.len;
    }
    return null;
}
