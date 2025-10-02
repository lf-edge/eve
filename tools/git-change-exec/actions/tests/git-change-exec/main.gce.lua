function isGCE(path)
	pattern = "^/?tools/git%-change%-exec/.*$"
	return path:find(pattern) ~= nil
end

function match(lf, ld)
	if not isGCE(lf:Path()) then
		return false
	end
	if ld:IsCommentString() == "comment" then
		return false
	end

	return true
end

function exec()
	ok, _, _ = os.execute("make -C tools/git-change-exec test")
	return ok
end
