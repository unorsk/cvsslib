const std = @import("std");
const cvss_score = @import("cvsslib.zig").cvss_score;

// CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);

    const stdout = bw.writer();

    if (args.len == 2) {
        std.debug.print("arg: {s}", .{args[1]});
        _ = try cvss_score(args[1]);
        try stdout.print("cvss: {s}", .{"cvss.CVSS31"});
    } else {
        try stdout.print("Too many or to few arguments!\n", .{});
    }

    try bw.flush(); // don't forget to flush!
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.

}
