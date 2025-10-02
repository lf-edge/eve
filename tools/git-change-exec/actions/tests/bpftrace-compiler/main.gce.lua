function isBpftraceCompilerFile(path)
	if path == "kernel-commits.mk" then
		return true
	end
	pattern = "^/?eve%-tools/bpftrace%-compiler/.*$"
	return path:find(pattern) ~= nil
end

function match(lf, ld)
	if not isBpftraceCompilerFile(lf:Path()) then
		return false
	end
	if ld:IsCommentString() == "comment" then
		return false
	end

	return true
end

function exec()
	ok, _, _ = os.execute("make -C eve-tools/bpftrace-compiler test")
	return ok
end
