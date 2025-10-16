function isPillarFile(path)
	pattern = "^/?pkg/pillar/.*$"
	return path:find(pattern) ~= nil
end

function match(lf, ld)
	if not isPillarFile(lf:Path()) then
		return false
	end
	if ld:IsCommentString() == "comment" then
		return false
	end

	return true
end

function exec()
	ok, _, _ = os.execute("make -C pkg/pillar test")
	return ok
end
