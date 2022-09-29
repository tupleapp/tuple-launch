const std = @import("std");
const crypt = @import("crypt.zig");
const Signer = std.crypto.sign.Ed25519;

// Blake3      : 1
// Blake2b512  : 1.3 x slower than Blake3
// Sha256      : 4 x slower than Blake3
//const Hasher = std.crypto.hash.sha2.Sha256;
//const Hasher = std.crypto.hash.blake2.Blake2b512;
const Hasher = std.crypto.hash.Blake3;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.os.exit(0xff);
}

pub fn main() !u8 {
    if (std.os.argv.len <= 1) {
        try std.io.getStdOut().writer().writeAll(
            "Generate new Key: signing genkey [--encrypt PASSWORD] SECRET_FILENAME PUBLIC_FILENAME\n" ++
            "Sign a file     : signing sign [--encrypt PASSWORD] SECRET_FILENAME FILENAME\n" ++
            "Verify a file   : signing verify PUBLIC_FILENAME FILENAME\n" ++
            "\n" ++
            "The sign/verify commands assume the signature will reside in FILENAME.sig\n" ++
            "The --encrypt PASSWORD option will store/read the secret key file encrypted using\n" ++
            "the given password to derive the encryption key.\n"
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

fn getCmdlineOption(args: [][*:0]u8, i: *usize) [*:0]u8 {
    i.* += 1;
    if (i.* >= args.len)
        fatal("option '{s}' requires an argument", .{args[i.* - 1]});

    return args[i.*];
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

fn sign(all_args: [][*:0]u8) !u8 {
    var encrypt_password: ?[]const u8 = null;
    const args = blk: {
        var i: usize = 0;
        var new_arg_count: usize = 0;
        while (i < all_args.len) : (i += 1) {
            const arg = std.mem.span(all_args[i]);
            if (!std.mem.startsWith(u8, arg, "-")) {
                all_args[new_arg_count] = arg;
                new_arg_count += 1;
            } else if (std.mem.eql(u8, arg, "--encrypt")) {
                encrypt_password = std.mem.span(getCmdlineOption(all_args, &i));
            } else {
                std.log.err("unknown cmd-line option '{s}'", .{arg});
                return 0xff;
            }
        }
        break :blk all_args[0 .. new_arg_count];
    };
    if (args.len != 2) {
        std.log.err("sign requires 2 arguments but got {}", .{args.len});
        return 0xff;
    }
    const secret_filename = std.mem.span(args[0]);
    const filename_to_sign = std.mem.span(args[1]);

    const pair = try loadKeyPair(secret_filename, encrypt_password);
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

fn genkey(all_args: [][*:0]u8) !u8 {
    var encrypt_password: ?[]const u8 = null;
    const args = blk: {
        var i: usize = 0;
        var new_arg_count: usize = 0;
        while (i < all_args.len) : (i += 1) {
            const arg = std.mem.span(all_args[i]);
            if (!std.mem.startsWith(u8, arg, "-")) {
                all_args[new_arg_count] = arg;
                new_arg_count += 1;
            } else if (std.mem.eql(u8, arg, "--encrypt")) {
                encrypt_password = std.mem.span(getCmdlineOption(all_args, &i));
            } else {
                std.log.err("unknown cmd-line option '{s}'", .{arg});
                return 0xff;
            }
        }
        break :blk all_args[0 .. new_arg_count];
    };
    if (args.len != 2) {
        std.log.err("genkey requires 2 arguments but got {}", .{args.len});
        return 0xff;
    }
    const secret_filename = std.mem.span(args[0]);
    const public_filename = std.mem.span(args[1]);

    const pair = try Signer.KeyPair.create(null);
    if (encrypt_password) |password| {
        const key = try crypt.passwordToKey(password);
        var tag: [crypt.tag_length]u8 = undefined;
        var encrypted_secret_key: [Signer.secret_length]u8 = undefined;
        try crypt.encrypt(key, &pair.secret_key, &tag, &encrypted_secret_key);
        var out_file = try std.fs.cwd().createFile(secret_filename, .{});
        defer out_file.close();
        try out_file.writer().print("encrypted: 1\ntag_hex: {}\ndata_hex: {}\n", .{
            std.fmt.fmtSliceHexUpper(&tag),
            std.fmt.fmtSliceHexUpper(&encrypted_secret_key),
        });
    } else {
        var out_file = try std.fs.cwd().createFile(secret_filename, .{});
        defer out_file.close();
        try out_file.writer().print("encrypted: 0\ndata_hex: {}\n", .{
            std.fmt.fmtSliceHexUpper(&pair.secret_key),
        });
    }
    try writeFileHex(public_filename, &pair.public_key);
    std.log.info("Success", .{});
    return 0;
}

fn nextNonEmptyLine(it: anytype) ?[]const u8 {
    while (it.next()) |raw_line| {
        const line = std.mem.trimLeft(u8, raw_line, " ");
        if (line.len > 0 and !std.mem.startsWith(u8, line, "#"))
            return line;
    }
    return null;
}

fn getField(filename: []const u8, it: anytype, expected: []const u8) []const u8 {
    const line = nextNonEmptyLine(it) orelse
        fatal("invalid secret key file '{s}': ended prematurely (expected '{s}')", .{filename, expected});
    if (!std.mem.startsWith(u8, line, expected))
        fatal("invalid secret key file '{s}': expected '{s}' but got '{s}'", .{filename, expected, line});
    return line[expected.len..];
}

fn invalidFieldLen(secret_filename: []const u8, field_name: []const u8, expected: usize, actual: usize) noreturn {
    fatal("invalid secret key file '{s}': {s} should be {} characters but is {}", .{secret_filename, field_name, expected, actual});
}

fn parseSecretDataHex(secret_filename: []const u8, it: anytype) [Signer.secret_length]u8 {
    const data_hex = getField(secret_filename, it, "data_hex: ");
    var data: [Signer.secret_length]u8 = undefined;
    const len = (std.fmt.hexToBytes(&data, data_hex) catch |err| switch (err) {
        error.InvalidCharacter => fatal("invalid secret key file '{s}': data_hex contains invalid hex characters", .{secret_filename}),
        error.NoSpaceLeft, error.InvalidLength => invalidFieldLen(secret_filename, "data_hex", data.len, data_hex.len),
    }).len;
    if (len != data.len) invalidFieldLen(secret_filename, "data_hex", data.len, data_hex.len);
    return data;
}

fn loadKeyPair(secret_filename: []const u8, optional_encrypted_password: ?[]const u8) !Signer.KeyPair {

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const content = blk: {
        std.log.info("DEBUG reading '{s}'...", .{secret_filename});
        var file = try std.fs.cwd().openFile(secret_filename, .{});
        defer file.close();
        break :blk try file.readToEndAlloc(arena.allocator(), 999999);
    };

    var it = std.mem.split(u8, content, "\n");

    const encrypted = blk: {
        const encrypted_value = getField(secret_filename, &it, "encrypted: ");
        if (std.mem.eql(u8, encrypted_value, "0")) break :blk false;
        if (std.mem.eql(u8, encrypted_value, "1")) break :blk true;
        fatal("invalid secret key file '{s}': invalid encrypted value '{s}'", .{secret_filename, encrypted_value});
    };

    const seed = seed_blk: {
        if (optional_encrypted_password) |password| {
            if (!encrypted)
                fatal("secret key file '{s}' is not encrypted but user provided a --encrypt PASSWORD", .{secret_filename});
            const tag = tag_blk: {
                const tag_hex = getField(secret_filename, &it, "tag_hex: ");
                var tag: [crypt.tag_length]u8 = undefined;
                const len = (std.fmt.hexToBytes(&tag, tag_hex) catch |err| switch (err) {
                    error.InvalidCharacter => fatal("invalid secret key file '{s}': tag_hex contains invalid hex characters", .{secret_filename}),
                    error.NoSpaceLeft, error.InvalidLength => invalidFieldLen(secret_filename, "tag_hex", tag.len, tag_hex.len),
                }).len;
                if (len != tag.len) invalidFieldLen(secret_filename, "tag_hex", tag.len, tag_hex.len);
                break :tag_blk tag;
            };
            const encrypted_data = parseSecretDataHex(secret_filename, &it);
            var unencrypted_data: [Signer.secret_length]u8 = undefined;
            const key = try crypt.passwordToKey(password);
            try crypt.decrypt(key, tag, &encrypted_data, &unencrypted_data);
            break :seed_blk unencrypted_data;
        } else {
            if (encrypted)
                fatal("secret key file '{s}' is encrypted, provide the password via --encrypt PASSWORD", .{secret_filename});
            break :seed_blk parseSecretDataHex(secret_filename, &it);
        }
    };
    if (nextNonEmptyLine(&it)) |extra|
        fatal("invalid secret key file '{s}': contains extra data starting at: '{s}'", .{secret_filename, extra});
    return Signer.KeyPair.fromSecretKey(seed);
}

fn readFileHex(filename: []const u8, comptime len: usize) ![len]u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const hex_len = len * 2;
    var content: [hex_len]u8 = undefined;
    {
        const read_len = try file.readAll(&content);
        if (read_len != hex_len)
            fatal("expected '{s}' to be {} bytes but is {}", .{filename, hex_len, read_len});
    }
    var bytes: [len]u8 = undefined;
    const bytes_len = (try std.fmt.hexToBytes(&bytes, &content)).len;
    if (len != bytes_len)
        fatal("'{s}' contained invalid hex characters", .{filename});
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
