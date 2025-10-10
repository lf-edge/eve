function isRelevantPath(path)
	dockerfilePattern = "^/?pkg/debug/Dockerfile$"
	makefilePattern = "^/?pkg/debug/Makefile$"
	sshPattern = "^/?pkg/debug/ssh/.*$"

	return
		path:find(dockerfilePattern) ~= nil or
		path:find(makefilePattern) ~= nil or
		path:find(sshPattern) ~= nil

end

function match(lf, ld)
	if not isRelevantPath(lf:Path()) then
		return false
	end
	if ld:IsCommentString() == "comment" then
		return false
	end

	return true
end

function exec()
	ok, _, _ = os.execute("make -C pkg/debug test-ssh")
	return ok
end
