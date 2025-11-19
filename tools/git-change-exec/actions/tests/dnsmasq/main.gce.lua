function isDnsmasq(path)
	pattern = "^/?pkg/dnsmasq/.*$"
	return path:find(pattern) ~= nil
end

function match(lf, ld)
	if not isDnsmasq(lf:Path()) then
		return false
	end
	if ld:IsCommentString() == "comment" then
		return false
	end

	return true
end

function exec()
	ok, _, _ = os.execute("make -C pkg/dnsmasq test")
	return ok
end
