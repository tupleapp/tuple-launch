const std = @import("std");
const Signer = std.crypto.sign.Ed25519;

// Blake3      : 1
// Blake2b512  : 1.3 x slower than Blake3
// Sha256      : 4 x slower than Blake3
//const Hasher = std.crypto.hash.sha2.Sha256;
//const Hasher = std.crypto.hash.blake2.Blake2b512;
const Hasher = std.crypto.hash.Blake3;

pub fn main() !u8 {
    if (std.os.argv.len <= 1) {
        try std.io.getStdOut().writer().writeAll(
            "Generate new Key: signing genkey SECRET_FILENAME PUBLIC_FILENAME\n" ++
            "Sign a file     : signing sign SECRET_FILENAME FILENAME\n" ++
            "Verify a file   : signing verify PUBLIC_FILENAME FILENAME\n" ++
            "\n" ++
            "The sign/verify commands assume the signature will reside in FILENAME.sig\n"
        );
        return 0xff;
    }
    const cmd = std.mem.span(std.os.argv.ptr[1]);
    const args = std.os.argv.ptr[2..std.os.argv.len];
    if (std.mem.eql(u8, cmd, "verify")) return try verify(args);
    if (std.mem.eql(u8, cmd, "sign")) return try sign(args);
    if (std.mem.eql(u8, cmd, "genkey")) return try genkey(args);
    std.log.err("unknown command '{s}'", .{cmd});
    return 0xff;
}

fn verify(args: [][*:0]u8) !u8 {
    if (args.len != 2) {
        std.log.err("verify requires 2 arguments but got {}", .{args.len});
        return 0xff;
    }
    const public_filename = std.mem.span(args[0]);
    const filename_to_verify = std.mem.span(args[1]);

    const public_key = try readFileHex(public_filename, Signer.public_length);
    const signature = blk: {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const filename = try std.fmt.allocPrint(arena.allocator(), "{s}.sig", .{filename_to_verify});
        break :blk try readFileHex(filename, Signer.signature_length);
    };

    const hash = try hashFile(filename_to_verify);
    std.log.info("hash is {}", .{std.fmt.fmtSliceHexUpper(&hash)});

    Signer.verify(signature, &hash, public_key) catch |err| switch (err) {
        error.SignatureVerificationFailed => {
            std.log.err("verification failed, data corrupted", .{});
            return 0xff;
        },
        else => |e| return e,
    };
    std.log.info("Success", .{});
    return 0;
}

fn sign(args: [][*:0]u8) !u8 {
    if (args.len != 2) {
        std.log.err("sign requires 2 arguments but got {}", .{args.len});
        return 0xff;
    }
    const secret_filename = std.mem.span(args[0]);
    const filename_to_sign = std.mem.span(args[1]);

    const pair = try loadKeyPair(secret_filename);
    const hash = try hashFile(filename_to_sign);
    std.log.info("hash is {}", .{std.fmt.fmtSliceHexUpper(&hash)});

    const signature = try Signer.sign(&hash, pair, null);
    std.log.info("signature is {}", .{std.fmt.fmtSliceHexUpper(&signature)});
    {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const filename = try std.fmt.allocPrint(arena.allocator(), "{s}.sig", .{filename_to_sign});
        try writeFileHex(filename, &signature);
    }
    std.log.info("Success", .{});
    return 0;
}

fn genkey(args: [][*:0]u8) !u8 {
    if (args.len != 2) {
        std.log.err("genkey requires 2 arguments but got {}", .{args.len});
        return 0xff;
    }
    const secret_filename = std.mem.span(args[0]);
    const public_filename = std.mem.span(args[1]);

    const pair = try Signer.KeyPair.create(null);
    try writeFileHex(secret_filename, &pair.secret_key);
    try writeFileHex(public_filename, &pair.public_key);
    std.log.info("Success", .{});
    return 0;
}

fn loadKeyPair(secret_filename: []const u8) !Signer.KeyPair {
    const seed = try readFileHex(secret_filename, Signer.secret_length);
    return Signer.KeyPair.fromSecretKey(seed);
}

fn readFileHex(filename: []const u8, comptime len: usize) ![len]u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const hex_len = len * 2;
    var content: [hex_len]u8 = undefined;
    {
        const read_len = try file.readAll(&content);
        if (read_len != hex_len) {
            std.log.err("expected '{s}' to be {} bytes but is {}", .{filename, hex_len, read_len});
            std.os.exit(0xff);
        }
    }
    var bytes: [len]u8 = undefined;
    const bytes_len = (try std.fmt.hexToBytes(&bytes, &content)).len;
    if (len != bytes_len) {
        std.log.err("'{s}' contained invalid hex characters", .{filename});
        std.os.exit(0xff);
    }
    return bytes;
}

fn writeFileHex(filename: []const u8, content: []const u8) !void {
    var out_file = try std.fs.cwd().createFile(filename, .{});
    defer out_file.close();
    try out_file.writer().print("{}", .{std.fmt.fmtSliceHexUpper(content)});
}

fn hashFile(filename: []const u8) ![Hasher.digest_length]u8 {
    var hash = Hasher.init(.{});
    {
        var file = try std.fs.cwd().openFile(filename, .{});
        defer file.close();
        while (true) {
            var buf: [std.mem.page_size]u8 = undefined;
            const len = try file.read(&buf);
            if (len == 0) break;
            //std.log.info("hashing {} bytes...", .{len});
            hash.update(buf[0 .. len]);
        }
    }
    var result: [Hasher.digest_length]u8 = undefined;
    hash.final(&result);
    return result;
}
