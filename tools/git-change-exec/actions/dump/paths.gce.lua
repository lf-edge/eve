paths = {}

function match(lf, ld)
	if paths[lf:Path()] ~= nil then
		return false
	end
	paths[lf:Path()] = true
	return true
end

function exec(as)
	for _, a in as() do
		print("path: " .. a.Path)
	end
	return true
end
