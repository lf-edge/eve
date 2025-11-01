function isRelevantPath(path)
	dockerfilePattern = "^/?pkg/debug/Dockerfile$"
	makefilePattern = "^/?pkg/debug/Makefile$"
	collectInfoPattern = "^/?pkg/debug/scripts/collect-info.sh$"
	abuildPattern = "^/?pkg/debug/scripts/abuild/.*$"
	lshwPattern = "^/?pkg/debug/scripts/lshw/.*$"
	return
		path:find(dockerfilePattern) ~= nil or
		path:find(makefilePattern) ~= nil or
		path:find(collectInfoPattern) ~= nil or
		path:find(abuildPattern) ~= nil or
		path:find(lshwPattern) ~= nil

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
	ok, _, _ = os.execute("make -C pkg/debug test-collect-info")
	return ok
end
